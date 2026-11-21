// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of the tool definitions, the catalog, `ghidra_help`, and the call validation.

use super::catalog::{merge_input_schema, Md5Rule};
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

/// Makes sure that the published bridge tools match the bridge MCP contract.
#[test]
fn bridge_tools_match_the_bridge_mcp_server() {
    let contract: Value =
        serde_json::from_str(include_str!("../../bridge/docs/mcp-tools.json")).expect("contract");
    let bridge_names: Vec<&str> = contract["tools"]
        .as_array()
        .expect("bridge tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("bridge tool name"))
        .collect();
    assert_eq!(bridge_names.len(), 56);
    assert_eq!(bridge_names[0], "ghidra_help");
    assert!(bridge_names.contains(&"ghidra_bridge_shutdown"));

    let expected_bridge: Vec<&str> = bridge_names
        .into_iter()
        .filter(|&name| name != "ghidra_help" && name != "ghidra_bridge_shutdown")
        .collect();
    assert_eq!(expected_bridge.len(), 54);

    let tools = tool_definitions();
    let actual_names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    assert_eq!(actual_names.len(), 65);
    assert_eq!(actual_names[0], "ghidra_help");

    let expected_set: BTreeSet<&str> = expected_bridge.iter().copied().collect();
    let actual_bridge: Vec<&str> = actual_names
        .iter()
        .copied()
        .filter(|name| expected_set.contains(name))
        .collect();
    assert_eq!(actual_bridge, expected_bridge);

    let local_only: BTreeSet<&str> = actual_names
        .into_iter()
        .filter(|&name| name != "ghidra_help" && !expected_set.contains(name))
        .collect();
    assert_eq!(
        local_only,
        BTreeSet::from([
            "ghidra_daemon_shutdown",
            "ghidra_daemon_status",
            "ghidra_job_get",
            "ghidra_job_list",
            "ghidra_job_wait",
            "ghidra_session_close",
            "ghidra_session_get",
            "ghidra_session_list",
            "ghidra_session_open",
            "ghidra_upload_prepare",
        ])
    );
}

/// Makes sure that the help tool is first, and that local operation tools have
/// flat typed schemas and accurate annotations.
#[test]
fn local_tool_definitions_have_typed_schemas_and_annotations() {
    let tools = tool_definitions();
    assert_eq!(tools[0]["name"], "ghidra_help");
    assert_eq!(tools[0]["annotations"]["readOnlyHint"], true);
    assert_eq!(tools[0]["annotations"]["destructiveHint"], false);
    assert_eq!(tools.len(), 65);
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    };

    assert!(tool("ghidra_session_open")["inputSchema"]
        .get("required")
        .is_none());
    let session_open = &tool("ghidra_session_open")["inputSchema"]["properties"];
    assert!(session_open["md5"].is_object());
    assert!(session_open["path"].is_object());
    assert!(session_open["wait"].is_object());
    assert_eq!(
        tool("ghidra_session_open")["annotations"]["destructiveHint"],
        false
    );
    assert_eq!(
        tool("ghidra_session_close")["inputSchema"]["required"],
        json!(["md5"])
    );
    assert_eq!(
        tool("ghidra_session_close")["annotations"]["destructiveHint"],
        true
    );
    assert_eq!(tool("ghidra_job_list")["annotations"]["readOnlyHint"], true);
    assert!(tool("ghidra_job_list")["inputSchema"]["properties"]
        .get("md5")
        .is_none());
    assert_eq!(
        tool("ghidra_job_get")["inputSchema"]["required"],
        json!(["jobId"])
    );
    assert_eq!(
        tool("ghidra_daemon_shutdown")["annotations"]["destructiveHint"],
        true
    );
    assert!(tool("ghidra_daemon_shutdown")["inputSchema"]["properties"]
        .get("md5")
        .is_none());
    assert_eq!(
        tool("ghidra_upload_prepare")["inputSchema"]["required"],
        json!(["md5", "fileName", "size"])
    );
    let analysis_props = &tool("ghidra_analysis_start")["inputSchema"]["properties"];
    assert!(analysis_props["md5"].is_object());
    assert!(analysis_props["analyzers"].is_object());
    assert!(analysis_props["wait"].is_object());
}

/// Makes sure that bridge operation tools merge `md5` with typed schemas and
/// preserve annotations.
#[test]
fn bridge_tool_definitions_have_typed_schemas_and_annotations() {
    let tools = tool_definitions();
    let tool = |name: &str| {
        tools
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("no tool {name}"))
    };
    assert_eq!(
        tool("ghidra_decompilation_get")["inputSchema"]["required"],
        json!(["md5", "selector"])
    );
    assert_eq!(
        tool("ghidra_decompilation_get")["annotations"]["readOnlyHint"],
        true
    );
    assert_eq!(
        tool("ghidra_decompilation_get")["annotations"]["destructiveHint"],
        false
    );
    assert_eq!(
        tool("ghidra_reference_list")["inputSchema"]["required"],
        json!(["md5", "filter"])
    );
    assert_eq!(
        tool("ghidra_reference_list")["annotations"]["readOnlyHint"],
        true
    );
    assert_eq!(
        tool("ghidra_comment_create")["inputSchema"]["required"],
        json!(["md5", "resource"])
    );
    assert_eq!(
        tool("ghidra_comment_create")["annotations"]["readOnlyHint"],
        false
    );
    assert_eq!(
        tool("ghidra_comment_create")["annotations"]["destructiveHint"],
        false
    );
    assert_eq!(
        tool("ghidra_program_save")["annotations"]["destructiveHint"],
        false
    );
    assert_eq!(
        tool("ghidra_memory_write")["inputSchema"]["required"],
        json!(["md5", "selector", "patch"])
    );
    assert_eq!(
        tool("ghidra_memory_write")["annotations"]["destructiveHint"],
        true
    );
    assert!(tool("ghidra_function_patch")["inputSchema"]["$defs"].is_object());
    assert!(tool("ghidra_bridge_get")["inputSchema"]
        .get("$defs")
        .is_none());
}

/// Makes sure that operation tools do not wrap parameters or require `ghidra_help` first.
#[test]
fn tool_definitions_are_direct_and_self_contained() {
    let tools = tool_definitions();
    for tool in &tools {
        let name = tool["name"].as_str().expect("tool name");
        let description = tool["description"].as_str().expect("description");
        assert!(
            !description.contains("Before the first call")
                && !description.contains("Before your first call"),
            "{name} description requires calling ghidra_help first: {description}"
        );
        if tool["annotations"]["readOnlyHint"] == true {
            assert_eq!(
                tool["annotations"]["destructiveHint"], false,
                "{name} is read-only and destructive"
            );
        }
    }
    for tool in &tools[1..] {
        let name = tool["name"].as_str().expect("tool name");
        let properties = tool["inputSchema"]["properties"]
            .as_object()
            .expect("properties");
        assert!(
            !properties.contains_key("params"),
            "{name} still wraps parameters in `params`"
        );
        assert!(
            !properties.contains_key("operation"),
            "{name} still uses `operation` discriminator"
        );
        if let Some(md5) = properties.get("md5") {
            let description = md5["description"].as_str().expect("md5 description");
            assert!(description.contains("32 hexadecimal characters"));
            assert!(description.contains("not a name or label"));
        }
    }
}

/// Makes sure that one error gives all absent parameters for both flat and legacy calls.
#[test]
fn missing_parameters_are_reported_together() {
    let flat_error = prepare(
        "ghidra_upload_prepare",
        object(json!({ "md5": "0123456789abcdef0123456789abcdef" })),
    )
    .err()
    .expect("missing flat parameters");
    assert!(reason(&flat_error).contains("`fileName`, `size`"));

    let legacy_error = prepare(
        "ghidra_upload",
        object(json!({
            "operation": "prepare",
            "md5": "0123456789abcdef0123456789abcdef",
            "params": {}
        })),
    )
    .err()
    .expect("missing legacy parameters");
    assert!(reason(&legacy_error).contains("`fileName`, `size`"));
}

/// Makes sure that each operation schema omits `md5` and that collisions panic.
#[test]
fn session_md5_is_never_an_operation_property() {
    for domain in super::catalog::domains() {
        for operation in &domain.operations {
            assert!(
                operation.schema["properties"].get("md5").is_none(),
                "{} {} has md5 in schema",
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

/// Makes sure that `merge_input_schema` rejects an operation schema that defines `md5`.
#[test]
#[should_panic(expected = "defines reserved top-level property `md5`")]
fn merge_input_schema_panics_on_md5_collision() {
    let colliding = json!({
        "type": "object",
        "properties": { "md5": { "type": "string" } }
    });
    let _ = merge_input_schema("ghidra_test_collision", Md5Rule::Required, &colliding);
}

/// Makes sure that Gemini and `rmcp` accept each public tool declaration.
#[test]
fn public_tool_contract_is_gemini_compatible() {
    assert_eq!(crate::mcp::ToolServer::tools().len(), 65);
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
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Makes sure that `analysis start` works through both flat and legacy tool calls.
#[test]
fn local_operation_extends_its_bridge_method() {
    let (flat_op, flat_req) = prepare(
        "ghidra_analysis_start",
        object(json!({
            "md5": "0123456789ABCDEF0123456789ABCDEF",
            "analyzers": ["Stack"],
            "wait": true
        })),
    )
    .expect("valid flat call");
    assert!(matches!(flat_op.route, Route::Local(_)));
    assert_eq!(
        flat_req.md5.as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
    assert_eq!(flat_req.label, "ghidra_analysis_start");
    assert_eq!(
        flat_req.params,
        json!({ "analyzers": ["Stack"], "wait": true })
    );

    let (legacy_op, legacy_req) = prepare(
        "ghidra_analysis",
        object(json!({
            "operation": "start",
            "md5": "0123456789ABCDEF0123456789ABCDEF",
            "params": { "analyzers": ["Stack"], "wait": true }
        })),
    )
    .expect("valid legacy call");
    assert!(matches!(legacy_op.route, Route::Local(_)));
    assert_eq!(legacy_req.label, "ghidra_analysis start");
}

/// Makes sure that bridge operations route to their bridge methods for flat and legacy calls.
#[test]
fn bridge_operation_uses_its_bridge_method() {
    let (decompile_op, decompile_req) = prepare(
        "ghidra_decompilation_get",
        object(json!({
            "md5": "0123456789abcdef0123456789abcdef",
            "selector": { "entry": "ram:00100000" },
            "format": "document"
        })),
    )
    .expect("valid flat bridge call");
    match &decompile_op.route {
        Route::Bridge(method) => assert_eq!(method, "decompilation.get"),
        Route::Local(_) => panic!("ghidra_decompilation_get must go to the bridge"),
    }
    assert_eq!(
        decompile_req.params,
        json!({ "selector": { "entry": "ram:00100000" }, "format": "document" })
    );

    let (bridge_op, bridge_req) = prepare(
        "ghidra_bridge",
        object(json!({ "operation": "get", "md5": "0123456789abcdef0123456789abcdef" })),
    )
    .expect("valid legacy bridge call");
    match &bridge_op.route {
        Route::Bridge(method) => assert_eq!(method, "session.get"),
        Route::Local(_) => panic!("ghidra_bridge get must go to the bridge"),
    }
    assert_eq!(bridge_req.params, json!({}));
}

/// Makes sure that `md5: null` is the same as no `md5` for flat and legacy calls.
#[test]
fn null_md5_is_no_md5() {
    let (_, flat_request) =
        prepare("ghidra_session_list", object(json!({ "md5": null }))).expect("flat null md5");
    assert!(flat_request.md5.is_none());
    let flat_error = prepare("ghidra_session_get", object(json!({ "md5": null })))
        .err()
        .expect("flat null md5 error");
    assert!(reason(&flat_error).contains("`ghidra_session_get` requires md5"));

    let (_, legacy_request) = prepare(
        "ghidra_session",
        object(json!({ "operation": "list", "md5": null })),
    )
    .expect("legacy null md5");
    assert!(legacy_request.md5.is_none());
    let legacy_error = prepare(
        "ghidra_session",
        object(json!({ "operation": "get", "md5": null })),
    )
    .err()
    .expect("legacy null md5 error");
    assert!(reason(&legacy_error).contains("`ghidra_session get` requires md5"));
}

/// Makes sure that `prepare` refuses invalid flat calls.
#[test]
fn prepare_refuses_invalid_flat_calls() {
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
            "ghidra_decompilation_get",
            json!({ "md5": md5 }),
            "requires parameter `selector`",
        ),
        (
            "ghidra_function_list",
            json!({ "md5": "x" }),
            "invalid arguments",
        ),
        (
            "ghidra_session_list",
            json!({ "operation": "list" }),
            "does not accept parameter `operation`",
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

/// Makes sure that `prepare` refuses invalid legacy domain calls.
#[test]
fn prepare_refuses_invalid_legacy_calls() {
    let md5 = "0123456789abcdef0123456789abcdef";
    let cases = [
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
    let block_list = memory["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .find(|operation| operation["name"] == "block.list")
        .expect("block.list");
    assert_eq!(block_list["tool"], "ghidra_memory_block_list");
    assert_eq!(block_list["md5"], "required");
    assert_eq!(block_list["effects"]["read_only"], true);

    let (_, direct_read) =
        help::run(object(json!({ "domain": "ghidra_memory_read" }))).expect("direct tool help");
    assert_eq!(direct_read["tool"], "ghidra_memory_read");
    assert_eq!(direct_read["operation"], "read");

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

/// Makes sure that flat and legacy job and daemon tools show the jobs.
#[tokio::test]
async fn job_list_and_daemon_status_show_jobs() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let job = daemon.state.insert_job("analysis", None);

    let (_, listed) = super::call(&daemon, "ghidra_job_list", Map::new())
        .await
        .unwrap();
    assert_eq!(listed["jobs"][0]["id"], job.id);
    let (_, status) = super::call(&daemon, "ghidra_daemon_status", Map::new())
        .await
        .unwrap();
    assert_eq!(status["daemon"]["pid"], std::process::id());
    assert_eq!(status["jobs"][0]["id"], job.id);

    let (_, legacy_listed) = super::call(
        &daemon,
        "ghidra_job",
        object(json!({ "operation": "list" })),
    )
    .await
    .unwrap();
    assert_eq!(legacy_listed["jobs"][0]["id"], job.id);
}

/// Makes sure that `ghidra_daemon_shutdown` refuses live work without `force`.
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
            "ghidra_daemon_shutdown",
            object(json!({ "force": force })),
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
