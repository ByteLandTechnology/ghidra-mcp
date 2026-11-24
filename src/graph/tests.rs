// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Unit and mock-bridge tests for `ghidra_graph callgraph` and `ghidra_graph basic_blocks`.

use super::{
    execute_batch, run_basic_blocks, run_callgraph, BatchItem, BatchOutcome, MAX_BATCH_ITEMS,
};
use crate::model::{RpcEnvelope, SessionRecord};
use crate::state::{test_state, ConnectionHandle, McpState};
use axum::extract::ws::Message;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Recorded JSON-RPC request frame received by the mock bridge.
#[derive(Clone, Debug)]
struct RecordedCall {
    /// Bridge method name.
    method: String,
    /// Bridge method parameters.
    params: Value,
}

/// Attaches an in-memory mock bridge to `md5` that answers each frame with `responder`.
fn spawn_mock_bridge(
    state: &Arc<McpState>,
    md5: &str,
    mut responder: impl FnMut(&str, &Value) -> Value + Send + 'static,
) -> Arc<Mutex<Vec<RecordedCall>>> {
    let conn_id = "mock-conn".to_string();
    let (sender, mut receiver) = mpsc::unbounded_channel::<Message>();
    let mut record = SessionRecord::launching(md5.to_string(), "binary".to_string(), "tok".into());
    record.mark_ready();
    state.put_session(&record).expect("put session");
    assert!(state.attach_bridge(
        md5,
        ConnectionHandle {
            conn_id: conn_id.clone(),
            sender,
        }
    ));

    let calls = Arc::new(Mutex::new(Vec::new()));
    let calls_clone = calls.clone();
    let state_clone = state.clone();
    let md5_owned = md5.to_string();

    tokio::spawn(async move {
        while let Some(Message::Text(wire)) = receiver.recv().await {
            let parsed: Value = serde_json::from_str(&wire).expect("valid JSON-RPC request");
            let id = parsed["id"].as_str().expect("request id").to_string();
            let method = parsed["method"].as_str().expect("method").to_string();
            let params = parsed["params"].clone();
            calls_clone.lock().expect("record lock").push(RecordedCall {
                method: method.clone(),
                params: params.clone(),
            });
            let result = responder(&method, &params);
            let mut envelope = RpcEnvelope::response(id.clone(), md5_owned.clone(), 200);
            envelope.result = Some(result);
            state_clone.deliver_response(&md5_owned, &conn_id, &id, envelope);
        }
    });

    calls
}

/// Checks that `execute_batch` splits requests larger than `MAX_BATCH_ITEMS` into valid chunks.
#[tokio::test]
async fn execute_batch_chunks_above_max_batch_items() {
    let root = tempfile::tempdir().expect("tempdir");
    let state = test_state(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";

    let calls = spawn_mock_bridge(&state, md5, |method, params| {
        assert_eq!(method, "batch.execute");
        let items = params["items"].as_array().expect("batch items");
        assert!(items.len() <= MAX_BATCH_ITEMS);
        let rows: Vec<Value> = items
            .iter()
            .map(|item| {
                json!({
                    "id": item["id"],
                    "result": { "echo": item["id"] }
                })
            })
            .collect();
        json!({ "items": rows })
    });

    let total = MAX_BATCH_ITEMS + 25;
    let items: Vec<BatchItem> = (0..total)
        .map(|idx| BatchItem {
            id: format!("item:{idx}"),
            method: "session.get",
            arguments: json!({}),
        })
        .collect();

    let outcomes = execute_batch(&state, md5, &items).await.expect("batch");
    assert_eq!(outcomes.len(), total);
    match outcomes.get("item:1024") {
        Some(BatchOutcome::Ok(val)) => assert_eq!(val["echo"], "item:1024"),
        other => panic!("unexpected outcome: {other:?}"),
    }
    let recorded = calls.lock().expect("lock");
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].params["items"].as_array().unwrap().len(), 1000);
    assert_eq!(recorded[1].params["items"].as_array().unwrap().len(), 25);
}

/// Builds a mock `function_call.list` response page for the call-graph test.
fn mock_callgraph_page(entry: &str, direction: &str, cursor: Option<&str>) -> Value {
    match (entry, direction, cursor) {
        ("00401000", "callers", None) => json!({
            "items": [{
                "entry": "00400f00",
                "name": "entry_caller",
                "call_site": "00400f12",
                "direction": "callers"
            }]
        }),
        ("00401000", "callees", None) => json!({
            "items": [{
                "entry": "00402000",
                "name": "helper_a",
                "call_site": "00401010",
                "direction": "callees"
            }],
            "next_cursor": "page2"
        }),
        ("00401000", "callees", Some("page2")) => json!({
            "items": [
                {
                    "entry": "00402000",
                    "name": "helper_a",
                    "call_site": "00401024",
                    "direction": "callees"
                },
                {
                    "entry": "00403000",
                    "name": "helper_b",
                    "call_site": "00401030",
                    "direction": "callees"
                }
            ]
        }),
        ("00402000", "callees", None) => json!({
            "items": [{
                "entry": "00404000",
                "name": "leaf_fn",
                "call_site": "00402008",
                "direction": "callees"
            }]
        }),
        _ => json!({ "items": [] }),
    }
}

/// Checks that `run_callgraph` sends one `batch.execute` wave per BFS hop, drains cursors,
/// aggregates multiple call sites, and enforces node and depth caps.
#[tokio::test]
async fn callgraph_batches_each_bfs_hop_and_collects_call_sites() {
    let root = tempfile::tempdir().expect("tempdir");
    let state = test_state(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";

    let calls = spawn_mock_bridge(&state, md5, |method, params| match method {
        "function.get" => {
            assert!(params["projection"]["fields"].is_array());
            json!({
                "entry": "00401000",
                "name": "main_fn",
                "namespace": "app",
                "demangled_name": "app::main_fn()"
            })
        }
        "batch.execute" => {
            let items = params["items"].as_array().expect("items");
            let rows: Vec<Value> = items
                .iter()
                .map(|item| {
                    let id = item["id"].as_str().unwrap();
                    let args = &item["arguments"];
                    assert_eq!(args["page"]["limit"], 1000);
                    let entry = args["filter"]["entry"].as_str().unwrap();
                    let direction = args["filter"]["direction"].as_str().unwrap();
                    let cursor = args.pointer("/page/cursor").and_then(Value::as_str);
                    json!({ "id": id, "result": mock_callgraph_page(entry, direction, cursor) })
                })
                .collect();
            json!({ "items": rows })
        }
        other => panic!("unexpected bridge method: {other}"),
    });

    let params = serde_json::from_value(json!({
        "entry": "00401000",
        "max_depth": 2
    }))
    .expect("params");
    let (_, payload) = run_callgraph(&state, md5, "ghidra_graph callgraph", params)
        .await
        .expect("callgraph");

    assert_eq!(payload["root"], "ram:00401000");
    assert_eq!(payload["hops"], 2);
    assert_eq!(payload["limited"], false);
    let nodes = payload["nodes"].as_array().expect("nodes");
    assert_eq!(nodes.len(), 5);
    let edges = payload["edges"].as_array().expect("edges");
    let helper_edge = edges
        .iter()
        .find(|edge| edge["from"] == "ram:00401000" && edge["to"] == "ram:00402000")
        .expect("helper_a edge");
    assert_eq!(helper_edge["sites"], json!(["00401010", "00401024"]));

    let recorded = calls.lock().expect("lock");
    // Expect 1 function.get, hop 1 batch, hop 1 cursor drain, and hop 2 batch.
    assert_eq!(recorded.len(), 4);
    assert_eq!(recorded[0].method, "function.get");
    assert_eq!(recorded[1].method, "batch.execute");
    assert_eq!(recorded[1].params["items"].as_array().unwrap().len(), 2);
    assert_eq!(recorded[2].method, "batch.execute");
    assert_eq!(recorded[2].params["items"].as_array().unwrap().len(), 1);
    assert_eq!(recorded[3].method, "batch.execute");
    assert_eq!(recorded[3].params["items"].as_array().unwrap().len(), 3);
}

/// Checks that `run_callgraph` enforces `max_nodes` and sets `limited = true`.
#[tokio::test]
async fn callgraph_respects_node_cap_and_expansion_sets() {
    let root = tempfile::tempdir().expect("tempdir");
    let state = test_state(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";

    let _calls = spawn_mock_bridge(&state, md5, |method, params| match method {
        "function.get" => json!({ "entry": "00401000", "name": "root_fn" }),
        "batch.execute" => {
            let items = params["items"].as_array().unwrap();
            let rows: Vec<Value> = items
                .iter()
                .map(|item| {
                    json!({
                        "id": item["id"],
                        "result": {
                            "items": [
                                {
                                    "entry": "00402000",
                                    "name": "callee_1",
                                    "call_site": "00401004"
                                },
                                {
                                    "entry": "00403000",
                                    "name": "callee_2",
                                    "call_site": "00401008"
                                }
                            ]
                        }
                    })
                })
                .collect();
            json!({ "items": rows })
        }
        other => panic!("unexpected method: {other}"),
    });

    let params = serde_json::from_value(json!({
        "entry": "00401000",
        "max_nodes": 2,
        "expansion": {
            "callers": [],
            "callees": ["ram:00401000"]
        }
    }))
    .expect("params");
    let (_, payload) = run_callgraph(&state, md5, "ghidra_graph callgraph", params)
        .await
        .expect("callgraph");

    assert_eq!(payload["limited"], true);
    assert_eq!(payload["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(
        payload["nodes"][0]["branches"]["callers"]["expanded"],
        false
    );
    assert_eq!(payload["nodes"][0]["branches"]["callees"]["expanded"], true);
    assert_eq!(payload["nodes"][0]["branches"]["callees"]["count"], 2);
}

/// Returns a mock bridge sub-response for the basic-block partition test.
fn mock_cfg_sub_response(sub_method: &str) -> Value {
    match sub_method {
        "function.get" => json!({
            "entry": "00401000",
            "name": "branch_fn",
            "body": { "start": "00401000", "end": "00401009", "num_addresses": 10 }
        }),
        "instruction.list" => json!({
            "items": [
                {
                    "address": "00401000",
                    "length": 2,
                    "mnemonic": "TEST",
                    "operands": ["EDI", "EDI"],
                    "flow_type": "FALL_THROUGH",
                    "fall_through": "00401002"
                },
                {
                    "address": "00401002",
                    "length": 2,
                    "mnemonic": "JZ",
                    "operands": ["0x00401008"],
                    "flow_type": "CONDITIONAL_JUMP",
                    "fall_through": "00401004"
                },
                {
                    "address": "00401004",
                    "length": 4,
                    "mnemonic": "MOV",
                    "operands": ["EAX", "0x1"],
                    "flow_type": "FALL_THROUGH",
                    "fall_through": "00401008"
                },
                {
                    "address": "00401008",
                    "length": 2,
                    "mnemonic": "RET",
                    "operands": [],
                    "flow_type": "TERMINATOR"
                },
                {
                    "address": "00401010",
                    "length": 1,
                    "mnemonic": "NOP",
                    "operands": [],
                    "flow_type": "FALL_THROUGH",
                    "fall_through": "00401011"
                }
            ]
        }),
        "reference.list" => json!({
            "items": [{ "from": "00401002", "to": "00401008", "type": "CONDITIONAL_JUMP" }]
        }),
        other => panic!("unexpected sub-method: {other}"),
    }
}

/// Checks that `run_basic_blocks` batches `function.get`, `instruction.list`, and
/// `reference.list` in one `batch.execute` call and partitions conditional and fall-through edges.
#[tokio::test]
async fn basic_blocks_batches_reads_and_partitions_cfg() {
    let root = tempfile::tempdir().expect("tempdir");
    let state = test_state(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";

    let calls = spawn_mock_bridge(&state, md5, |method, params| {
        assert_eq!(method, "batch.execute");
        let items = params["items"].as_array().expect("batch items");
        let rows: Vec<Value> = items
            .iter()
            .map(|item| {
                let id = item["id"].as_str().unwrap();
                let sub_method = item["method"].as_str().unwrap();
                let sub_args = &item["arguments"];
                match sub_method {
                    "function.get" => assert!(sub_args["projection"]["fields"].is_array()),
                    "instruction.list" => {
                        assert!(sub_args["scan"]["range"].is_object());
                        assert_eq!(sub_args["page"]["limit"], 1000);
                    }
                    "reference.list" => assert_eq!(sub_args["page"]["limit"], 1000),
                    _ => {}
                }
                json!({ "id": id, "result": mock_cfg_sub_response(sub_method) })
            })
            .collect();
        json!({ "items": rows })
    });

    let params = serde_json::from_value(json!({ "entry": "00401000" })).expect("params");
    let (_, payload) = run_basic_blocks(&state, md5, "ghidra_graph basic_blocks", params)
        .await
        .expect("basic_blocks");

    let recorded = calls.lock().expect("lock");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].params["items"].as_array().unwrap().len(), 3);

    assert_eq!(payload["has_body"], true);
    assert_eq!(payload["unresolved_jumps"], 0);
    let blocks = payload["blocks"].as_array().expect("blocks");
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0]["address"], "00401000");
    assert_eq!(blocks[0]["instruction_count"], 2);
    assert_eq!(blocks[1]["address"], "00401004");
    assert_eq!(blocks[1]["instruction_count"], 1);
    assert_eq!(blocks[2]["address"], "00401008");
    assert_eq!(blocks[2]["instruction_count"], 1);

    let edges = payload["edges"].as_array().expect("edges");
    assert_eq!(
        edges,
        &vec![
            json!({
                "from": "block:0",
                "to": "block:2",
                "label": "CONDITIONAL_JUMP",
                "kind": "taken"
            }),
            json!({
                "from": "block:0",
                "to": "block:1",
                "label": "Fall through",
                "kind": "fallthrough"
            }),
            json!({
                "from": "block:1",
                "to": "block:2",
                "label": "",
                "kind": "flow"
            })
        ]
    );
}
