// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of background analysis jobs, cancellation, and terminal error causes.

use crate::error::DomainError;
use crate::model::{job_kind, RpcEnvelope, SessionRecord};
use crate::state::{test_state, ConnectionHandle};
use crate::tools::{call, Control, Daemon};
use crate::upload::UploadService;
use axum::extract::ws::Message;
use serde_json::{json, Map, Value};
use std::path::Path;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Returns the arguments object of a JSON value.
fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        panic!("{value} is not a JSON object");
    };
    map
}

/// Returns the reason of an invalid-argument domain error.
fn reason(error: &anyhow::Error) -> String {
    match error.downcast_ref::<DomainError>() {
        Some(DomainError::InvalidArgument { reason, .. }) => reason.clone(),
        other => panic!("unexpected error: {other:?}"),
    }
}

/// Makes a daemon without Ghidra processes, for analysis and job tool tests.
fn test_daemon(root: &Path) -> Daemon {
    let state = test_state(root);
    std::fs::create_dir_all(&state.paths.tmp_dir).unwrap();
    let authorities = ["127.0.0.1:1".to_string(), "localhost:1".to_string()];
    let uploads = UploadService::new(state.clone(), authorities, CancellationToken::new()).unwrap();
    Daemon {
        state,
        uploads,
        control: Control::default(),
    }
}

/// Makes sure that `ghidra_job cancel` refuses launch jobs and returns finished analysis jobs.
#[tokio::test]
async fn job_cancel_refuses_launch_jobs_and_returns_finished_analysis_jobs() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";

    for kind in [
        job_kind::ANALYZE_BINARY,
        job_kind::ATTACH_SESSION,
        job_kind::RECOVER_SESSION_BRIDGE,
    ] {
        let launch_job = daemon.state.insert_job(kind, Some(md5.into()));
        let error = call(
            &daemon,
            "ghidra_job",
            object(json!({ "operation": "cancel", "params": { "jobId": launch_job.id } })),
        )
        .await
        .unwrap_err();
        let message = reason(&error);
        assert!(message.contains("ghidra_session close"), "{message}");
    }

    let completed = daemon
        .state
        .insert_job(job_kind::START_ANALYSIS, Some(md5.into()));
    daemon.state.finish_job(
        &completed.id,
        Ok(json!({ "analysis": { "status": "completed" } })),
    );
    let (_, done) = call(
        &daemon,
        "ghidra_job",
        object(json!({
            "operation": "cancel",
            "params": { "jobId": completed.id, "wait": true }
        })),
    )
    .await
    .unwrap();
    assert_eq!(done["job"]["status"], "completed");

    let failed = daemon
        .state
        .insert_job(job_kind::START_ANALYSIS, Some(md5.into()));
    daemon
        .state
        .finish_job(&failed.id, Err(DomainError::transaction_failed("boom")));
    let (_, done_failed) = call(
        &daemon,
        "ghidra_job",
        object(json!({
            "operation": "cancel",
            "params": { "jobId": failed.id, "wait": true }
        })),
    )
    .await
    .unwrap();
    assert_eq!(done_failed["job"]["status"], "failed");
    assert!(done_failed["job"]["error"]
        .as_str()
        .unwrap()
        .contains("boom"));
}

/// Makes sure that `ghidra_job cancel` stops a live analysis job and keeps the bridge error.
#[tokio::test]
async fn job_cancel_stops_live_analysis_and_propagates_error() {
    let root = tempfile::tempdir().unwrap();
    let daemon = test_daemon(root.path());
    let md5 = "0123456789abcdef0123456789abcdef";
    let mut record = SessionRecord::launching(md5.into(), "bin".into(), "t".into());
    record.mark_ready();
    daemon.state.put_session(&record).unwrap();

    let (sender, mut receiver) = mpsc::unbounded_channel();
    let conn_id = "conn-1".to_string();
    assert!(daemon.state.attach_bridge(
        md5,
        ConnectionHandle {
            conn_id: conn_id.clone(),
            sender,
        }
    ));

    let state = daemon.state.clone();
    let responder = tokio::spawn(async move {
        let mut cancelled = false;
        while let Some(Message::Text(frame)) = receiver.recv().await {
            let rpc: Value = serde_json::from_str(&frame).unwrap();
            let id = rpc["id"].as_str().unwrap().to_string();
            let method = rpc["method"].as_str().unwrap();
            let snapshot = match method {
                "analysis.start" => json!({ "status": "running", "progress": 10 }),
                "analysis.cancel" => {
                    cancelled = true;
                    json!({ "status": "running", "progress": 25 })
                }
                "analysis.get" if cancelled => json!({
                    "status": "cancelled",
                    "progress": 25,
                    "error": "analysis cancelled: cancelled by user"
                }),
                "analysis.get" => json!({ "status": "running", "progress": 15 }),
                other => panic!("unexpected method {other}"),
            };
            let mut envelope = RpcEnvelope::response(id.clone(), md5.into(), 200);
            envelope.result = Some(snapshot);
            state.deliver_response(md5, &conn_id, &id, envelope);
        }
    });

    let (_, started) = call(
        &daemon,
        "ghidra_analysis",
        object(json!({ "operation": "start", "md5": md5, "params": {} })),
    )
    .await
    .unwrap();
    let job_id = started["job"]["id"].as_str().unwrap().to_string();

    let (_, first) = call(
        &daemon,
        "ghidra_job",
        object(json!({
            "operation": "cancel",
            "params": { "jobId": job_id, "wait": true, "timeoutMs": 5000 }
        })),
    )
    .await
    .unwrap();
    assert_eq!(first["job"]["status"], "failed");
    assert!(first["job"]["error"]
        .as_str()
        .unwrap()
        .contains("analysis cancelled: cancelled by user"));

    let (_, second) = call(
        &daemon,
        "ghidra_job",
        object(json!({
            "operation": "cancel",
            "params": { "jobId": job_id, "wait": true }
        })),
    )
    .await
    .unwrap();
    assert_eq!(second["job"]["status"], "failed");
    assert_eq!(second["job"]["error"], first["job"]["error"]);
    responder.abort();
}
