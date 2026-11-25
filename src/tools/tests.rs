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
    // The daemon hides `shutdown`: `ghidra_session close` stops the bridge.
    let bridge = expected.get_mut("ghidra_bridge").expect("ghidra_bridge");
    let count = bridge.len();
    bridge.retain(|operation| operation != "shutdown");
    assert_eq!(
        bridge.len() + 1,
        count,
        "the bridge has no shutdown operation"
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
            "ghidra_job",
            "ghidra_session",
            "ghidra_upload"
        ])
    );
}

/// Makes sure that the help tool is first, and that each domain tool has the
/// correct required arguments and annotations.
#[test]
fn tool_definitions_have_routes_and_annotations() {
    let tools = tool_definitions();
    assert_eq!(tools[0]["name"], "ghidra_help");
    assert_eq!(tools.len(), 19);
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
        tool("ghidra_function")["inputSchema"]["required"],
        json!(["operation", "md5"])
    );
    assert_eq!(
        tool("ghidra_analysis")["inputSchema"]["required"],
        json!(["operation", "md5"])
    );
    assert_eq!(
        tool("ghidra_decompilation")["annotations"]["readOnlyHint"],
        true
    );
    assert_eq!(
        tool("ghidra_memory")["annotations"]["destructiveHint"],
        true
    );
    assert_eq!(tool("ghidra_job")["annotations"]["readOnlyHint"], true);
    assert_eq!(
        tool("ghidra_session")["annotations"]["destructiveHint"],
        true
    );

    assert_eq!(
        tool("ghidra_daemon")["annotations"]["destructiveHint"],
        true
    );
    assert!(tool("ghidra_daemon")["inputSchema"]["properties"]
        .get("md5")
        .is_none());

    let session = &tool("ghidra_session")["inputSchema"]["properties"];
    assert!(session["md5"].is_object());
    let job = &tool("ghidra_job")["inputSchema"]["properties"];
    assert!(job.get("md5").is_none());
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
    assert!(rule("session", "open") == Md5Rule::Optional);
    assert!(rule("session", "get") == Md5Rule::Required);
    assert!(rule("session", "close") == Md5Rule::Required);
    assert!(rule("session", "checkpoint.create") == Md5Rule::Required);
    assert!(rule("session", "checkpoint.list") == Md5Rule::Required);
    assert!(rule("session", "checkpoint.restore") == Md5Rule::Required);
    assert!(rule("session", "reset") == Md5Rule::Required);
    assert!(rule("session", "delete") == Md5Rule::Required);
    assert!(rule("session", "list") == Md5Rule::Absent);
    assert!(rule("upload", "prepare") == Md5Rule::Required);
    assert!(rule("job", "wait") == Md5Rule::Absent);
}

/// Makes sure that Gemini can use each public tool as a function declaration.
#[test]
fn public_tool_contract_is_gemini_compatible() {
    let tools = tool_definitions();
    assert_eq!(tools.len(), 19);
    for tool in &tools {
        let name = tool["name"].as_str().expect("tool name");
        assert!(valid_function_name(name), "tool name {name}");

        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].is_object());
        assert_no_unsupported_schema_keys(name, schema);
        assert!(tool.get("outputSchema").is_none());

        if name != "ghidra_help" {
            let params = &schema["properties"]["params"];
            assert_eq!(params["type"], "object", "{name} params type");
            let param_props = params["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{name} params.properties must be an object"));
            assert!(
                !param_props.is_empty(),
                "{name} must publish non-empty params.properties"
            );
        }
    }

    let tool = |name: &str| {
        tools
            .iter()
            .find(|item| item["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    };
    let listing_description = tool("ghidra_listing")["description"]
        .as_str()
        .expect("listing description");
    assert!(listing_description.contains("data units"));
    assert!(listing_description.contains("basic blocks"));
    assert_eq!(
        tool("ghidra_upload")["inputSchema"]["properties"]["params"]["required"],
        json!(["fileName", "size"])
    );
    assert_eq!(
        tool("ghidra_decompilation")["inputSchema"]["properties"]["params"]["required"],
        json!(["selector"])
    );
    let reference_params = &tool("ghidra_reference")["inputSchema"]["properties"]["params"];
    assert!(reference_params.get("required").is_none());
    assert!(reference_params["properties"]["filter"].is_object());
    assert!(reference_params["properties"]["scan"].is_object());
    assert_eq!(
        tool("ghidra_batch")["inputSchema"]["properties"]["params"]["required"],
        json!(["items"])
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
    let prepared = prepare(
        "ghidra_analysis",
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
    assert_eq!(request.label, "ghidra_analysis start");
}

/// Makes sure that a bridge operation goes to its bridge method.
#[test]
fn bridge_operation_uses_its_bridge_method() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let prepared = prepare(
        "ghidra_bridge",
        object(json!({ "operation": "get", "md5": md5 })),
    )
    .expect("valid call");
    let (operation, request) = prepared;
    match &operation.route {
        Route::Bridge(method) => assert_eq!(method, "session.get"),
        Route::Local(_) => panic!("ghidra_bridge get must go to the bridge"),
    }
    assert_eq!(request.params, json!({}));

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
    assert_eq!(block_list["md5"], "required");
    assert_eq!(block_list["effects"]["read_only"], true);
    assert!(block_list["inputSchema"]["properties"].is_object());

    let (_, open) = help::run(object(
        json!({ "domain": "ghidra_session", "operation": "open" }),
    ))
    .expect("operation");
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

    let (_, listed) = call("ghidra_job", "list").await.unwrap();
    assert_eq!(listed["jobs"][0]["id"], job.id);
    let (_, status) = call("ghidra_daemon", "status").await.unwrap();
    assert_eq!(status["daemon"]["pid"], std::process::id());
    assert_eq!(status["jobs"][0]["id"], job.id);
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

/// Makes sure that `Route::Bridge` moves `RpcEnvelope.result` into the output map without clones.
#[tokio::test]
async fn bridge_call_moves_envelope_result_without_clones() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";
    let mut record = crate::model::SessionRecord::launching(md5.into(), "bin".into(), "t".into());
    record.mark_ready();
    daemon.state.put_session(&record).unwrap();

    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    assert!(daemon.state.attach_bridge(
        md5,
        crate::state::ConnectionHandle {
            conn_id: "conn-1".into(),
            sender,
        },
    ));

    let payload = String::from("0x00401000 entry_point");
    let payload_ptr = payload.as_ptr();
    let state = daemon.state.clone();
    let responder = tokio::spawn(async move {
        let Some(axum::extract::ws::Message::Text(frame)) = receiver.recv().await else {
            panic!("expected bridge text frame");
        };
        let req: Value = serde_json::from_str(&frame).unwrap();
        let req_id = req["id"].as_str().unwrap().to_string();
        let mut envelope = crate::model::RpcEnvelope::response(req_id.clone(), md5.into(), 200);
        envelope.result = Some(Value::Object(Map::from_iter([(
            "function".to_string(),
            Value::String(payload),
        )])));
        state.deliver_response(md5, "conn-1", &req_id, envelope);
    });

    let (summary, structured) = super::call(
        &daemon,
        "ghidra_function",
        object(json!({ "operation": "list", "md5": md5 })),
    )
    .await
    .unwrap();
    responder.await.unwrap();
    assert_eq!(summary, "ghidra_function list completed");
    assert_eq!(structured["response"]["status"], 200);
    assert_eq!(
        structured["response"]["result"]["function"]
            .as_str()
            .unwrap()
            .as_ptr(),
        payload_ptr
    );
}

mod checkpoints;
