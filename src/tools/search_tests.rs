// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Integration tests for `ghidra_search` cache snapshots, disk persistence, and byte scans.

use super::{call, Control, Daemon};
use crate::model::{job_kind, RpcEnvelope, SessionRecord};
use crate::state::ConnectionHandle;
use axum::extract::ws::Message;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Converts a JSON value into an argument map.
fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        panic!("expected JSON object");
    };
    map
}

/// Builds an isolated test daemon with Ghidra project files for `md5`.
fn make_daemon(root: &Path, md5: &str) -> Daemon {
    let state = crate::state::test_state(root);
    fs::create_dir_all(&state.paths.tmp_dir).unwrap();
    let ghidra = state.paths.ghidra_project_root(md5);
    let rep = ghidra.join("project.rep").join("idata").join("00");
    fs::create_dir_all(&rep).unwrap();
    fs::write(ghidra.join("project.gpr"), b"<project/>").unwrap();
    fs::write(rep.join("00000000.prp"), b"STATE=1").unwrap();
    fs::write(rep.join("00000000.gbf"), vec![0x22u8; 512]).unwrap();
    let authorities = ["127.0.0.1:1".to_string(), "localhost:1".to_string()];
    let uploads = crate::upload::UploadService::new(
        state.clone(),
        authorities,
        tokio_util::sync::CancellationToken::new(),
    )
    .unwrap();
    Daemon {
        state,
        uploads,
        control: Control::default(),
    }
}

/// Attaches a fake ready bridge connection that answers bridge requests with `responder`.
fn attach_mock_bridge<F>(daemon: &Daemon, md5: &str, conn_id: &str, mut responder: F)
where
    F: FnMut(&str, &Value) -> Value + Send + 'static,
{
    let mut record = SessionRecord::launching(md5.into(), "sample.bin".into(), "tok".into());
    record.mark_ready();
    daemon.state.put_session(&record).unwrap();

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let connected = daemon.state.attach_bridge(
        md5,
        ConnectionHandle {
            conn_id: conn_id.to_string(),
            sender: tx,
        },
    );
    assert!(connected, "bridge connection must attach");

    let state = daemon.state.clone();
    let session_id = md5.to_string();
    let cid = conn_id.to_string();
    tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            let Message::Text(raw) = message else {
                continue;
            };
            let req: Value = serde_json::from_str(&raw).unwrap();
            let req_id = req["id"].as_str().unwrap().to_string();
            let method = req["method"].as_str().unwrap();
            let params = &req["params"];
            let result = responder(method, params);
            let mut env = RpcEnvelope::response(req_id.clone(), session_id.clone(), 200);
            env.result = Some(result);
            state.deliver_response(&session_id, &cid, &req_id, env);
        }
    });
}

/// Returns a sample `search.strings` bridge payload with two items.
fn sample_strings_payload() -> Value {
    json!({
        "items": [
            {
                "address": "ram:00401000",
                "value": "https://api.example.com/v1/auth",
                "length": 32,
                "encoding": "ascii",
                "defined": true
            },
            {
                "address": "ram:00402000",
                "value": "WideTokenValue",
                "length": 30,
                "encoding": "utf16le",
                "defined": false
            }
        ],
        "index_complete": true,
        "total_indexed": 2,
        "modification_number": 7
    })
}

/// Verifies snapshot hydration and zero-scan reopened session queries.
#[tokio::test]
async fn persists_string_snapshot_across_reopen_without_cold_scan() {
    let root = tempfile::tempdir().unwrap();
    let md5 = "0123456789abcdef0123456789abcdef";
    let daemon = make_daemon(root.path(), md5);
    let scans = Arc::new(AtomicUsize::new(0));
    let scans_ref = scans.clone();

    attach_mock_bridge(
        &daemon,
        md5,
        "conn-1",
        move |method, _params| match method {
            "search.strings" => {
                scans_ref.fetch_add(1, Ordering::SeqCst);
                sample_strings_payload()
            }
            "session.shutdown" => json!({ "shutting_down": true }),
            other => panic!("unexpected method {other}"),
        },
    );

    let (_, first) = call(
        &daemon,
        "ghidra_search",
        object(json!({
            "operation": "strings",
            "md5": md5,
            "params": { "filter": { "query": "example.com" } }
        })),
    )
    .await
    .unwrap();
    assert_eq!(scans.load(Ordering::SeqCst), 1);
    assert_eq!(first["response"]["result"]["index_complete"], true);
    assert!(first["response"]["result"]["items"][0]
        .get("bytes")
        .is_none());
    assert!(daemon.state.paths.string_index_file(md5).is_file());

    let (_, second) = call(
        &daemon,
        "ghidra_search",
        object(json!({
            "operation": "strings",
            "md5": md5,
            "params": { "filter": { "regex": "widetoken[a-z]+" } }
        })),
    )
    .await
    .unwrap();
    assert_eq!(scans.load(Ordering::SeqCst), 1);
    assert_eq!(
        second["response"]["result"]["items"][0]["address"],
        "ram:00402000"
    );

    let (_, help) = call(
        &daemon,
        "ghidra_help",
        object(json!({ "domain": "ghidra_search", "operation": "strings" })),
    )
    .await
    .unwrap();
    assert_eq!(
        help["inputSchema"]["properties"]["filter"]["properties"]["regex"]["type"],
        "string"
    );

    crate::session::close(&daemon.state, md5, false)
        .await
        .unwrap();
    daemon
        .state
        .string_index
        .on_session_launching(&daemon.state.paths, md5, true);

    let reopen_scans = Arc::new(AtomicUsize::new(0));
    let reopen_ref = reopen_scans.clone();
    attach_mock_bridge(
        &daemon,
        md5,
        "conn-2",
        move |method, _params| match method {
            "search.strings" => {
                reopen_ref.fetch_add(1, Ordering::SeqCst);
                sample_strings_payload()
            }
            other => panic!("unexpected method {other}"),
        },
    );

    let (_, reopened) = call(
        &daemon,
        "ghidra_search",
        object(json!({
            "operation": "strings",
            "md5": md5,
            "params": { "filter": { "encoding": "utf16" } }
        })),
    )
    .await
    .unwrap();
    assert_eq!(reopen_scans.load(Ordering::SeqCst), 0);
    assert_eq!(
        reopened["response"]["result"]["items"][0]["value"],
        "WideTokenValue"
    );
}

/// Verifies snapshot rebuild when an external tool edits the Ghidra project directory.
#[tokio::test]
async fn rebuilds_persisted_snapshot_after_external_project_edit() {
    let root = tempfile::tempdir().unwrap();
    let md5 = "1123456789abcdef0123456789abcdef";
    let daemon = make_daemon(root.path(), md5);
    let scans = Arc::new(AtomicUsize::new(0));
    let scans_ref = scans.clone();

    attach_mock_bridge(
        &daemon,
        md5,
        "conn-ext",
        move |method, _params| match method {
            "search.strings" => {
                let n = scans_ref.fetch_add(1, Ordering::SeqCst);
                json!({
                    "items": [{
                        "address": "ram:00403000",
                        "value": format!("Generation-{n}"),
                        "length": 13,
                        "encoding": "ascii",
                        "defined": true
                    }],
                    "index_complete": true,
                    "total_indexed": 1,
                    "modification_number": n + 1
                })
            }
            other => panic!("unexpected method {other}"),
        },
    );

    let (_, initial) = call(
        &daemon,
        "ghidra_search",
        object(json!({ "operation": "strings", "md5": md5 })),
    )
    .await
    .unwrap();
    assert_eq!(
        initial["response"]["result"]["items"][0]["value"],
        "Generation-0"
    );
    assert_eq!(scans.load(Ordering::SeqCst), 1);

    let gbf_path = daemon
        .state
        .paths
        .ghidra_project_root(md5)
        .join("project.rep")
        .join("idata")
        .join("00")
        .join("00000000.gbf");
    let mut edited = vec![0x22u8; 512];
    edited[16] = 0xfe;
    fs::write(gbf_path, edited).unwrap();

    let (_, rebuilt) = call(
        &daemon,
        "ghidra_search",
        object(json!({ "operation": "strings", "md5": md5 })),
    )
    .await
    .unwrap();
    assert_eq!(scans.load(Ordering::SeqCst), 2);
    assert_eq!(
        rebuilt["response"]["result"]["items"][0]["value"],
        "Generation-1"
    );
}

/// Returns a sample `search.bytes` bridge payload for `pattern`.
fn sample_bytes_payload(pattern: &Value) -> Value {
    json!({
        "items": [{
            "index": 0,
            "pattern": pattern,
            "matches": ["ram:00401010"],
            "match_count": 1
        }],
        "total_matches": 1,
        "scan": {
            "scanned_bytes": 64,
            "timed_out": false
        }
    })
}

/// Verifies invalidation on program mutations, incomplete results during analysis, and byte scans.
#[tokio::test]
async fn invalidates_on_mutation_marks_analysis_incomplete_and_forwards_bytes() {
    let root = tempfile::tempdir().unwrap();
    let md5 = "fedcba9876543210fedcba9876543210";
    let daemon = make_daemon(root.path(), md5);
    let scans = Arc::new(AtomicUsize::new(0));
    let scans_ref = scans.clone();

    attach_mock_bridge(&daemon, md5, "conn-a", move |method, params| match method {
        "search.strings" => {
            let n = scans_ref.fetch_add(1, Ordering::SeqCst);
            json!({
                "items": [{
                    "address": "ram:00401000",
                    "value": format!("Version-{n}"),
                    "length": 10,
                    "encoding": "ascii",
                    "defined": n != 1
                }],
                "index_complete": n != 1,
                "total_indexed": 1,
                "modification_number": n + 1
            })
        }
        "memory.write" => json!({ "address": "ram:00401000", "length": 4 }),
        "search.bytes" => sample_bytes_payload(&params["patterns"][0]),
        other => panic!("unexpected method {other}"),
    });

    let (_, v0) = call(
        &daemon,
        "ghidra_search",
        object(json!({ "operation": "strings", "md5": md5 })),
    )
    .await
    .unwrap();
    assert_eq!(v0["response"]["result"]["items"][0]["value"], "Version-0");

    let job = daemon
        .state
        .insert_job(job_kind::START_ANALYSIS, Some(md5.to_string()));
    let (_, partial) = call(
        &daemon,
        "ghidra_search",
        object(json!({ "operation": "strings", "md5": md5 })),
    )
    .await
    .unwrap();
    assert_eq!(partial["response"]["result"]["index_complete"], false);
    assert!(!daemon.state.paths.string_index_file(md5).exists());
    daemon.state.finish_job(&job.id, Ok(json!({})));

    let (_, v2) = call(
        &daemon,
        "ghidra_search",
        object(json!({ "operation": "strings", "md5": md5 })),
    )
    .await
    .unwrap();
    assert_eq!(v2["response"]["result"]["items"][0]["value"], "Version-2");

    // Program mutation (`ghidra_memory write`) invalidates snapshot and forces rebuild.
    call(
        &daemon,
        "ghidra_memory",
        object(json!({
            "operation": "write",
            "md5": md5,
            "params": {
                "selector": { "address": "ram:00401000" },
                "patch": { "bytes": "90909090" }
            }
        })),
    )
    .await
    .unwrap();
    assert!(!daemon.state.paths.string_index_file(md5).exists());

    let (_, v3) = call(
        &daemon,
        "ghidra_search",
        object(json!({ "operation": "strings", "md5": md5 })),
    )
    .await
    .unwrap();
    assert_eq!(v3["response"]["result"]["items"][0]["value"], "Version-3");

    let (_, bytes_res) = call(
        &daemon,
        "ghidra_search",
        object(json!({
            "operation": "bytes",
            "md5": md5,
            "params": { "patterns": ["48 8b ?? ?? 90"] }
        })),
    )
    .await
    .unwrap();
    assert_eq!(
        bytes_res["response"]["result"]["items"][0]["matches"],
        json!(["ram:00401010"])
    );
}
