// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Ghidra auto-analysis as a background job.
//!
//! The bridge runs the analysis in a background task. `analysis.start` returns
//! a status snapshot at once. `analysis.get` then reports the progress until the
//! status is `completed`, `failed`, `cancelled` or `idle`. The job copies the
//! progress fields of each snapshot. Then `job.get` can show them.

use crate::error::DomainError;
use crate::model::{job_kind, JobRecord, RpcEnvelope, SessionStatus};
use crate::session;
use crate::state::McpState;
use anyhow::Result;
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::Duration;

/// The interval between requests for the analysis status from `analysis.get`.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum consecutive status errors before the job fails.
const MAX_CONSECUTIVE_POLL_FAILURES: usize = 10;

/// Starts the analysis. If the bridge has no connection, it first relaunches
/// the bridge. If `wait` has a value, it waits for the job.
pub async fn start(
    state: &Arc<McpState>,
    md5: String,
    params: Map<String, Value>,
    wait: Option<Duration>,
) -> Result<JobRecord> {
    let status = state.session(&md5)?.status;
    if status.is_recoverable() || status.is_launching() {
        session::ensure_connected(state, &md5).await?;
    }
    if state.session(&md5)?.status != SessionStatus::Ready {
        return Err(DomainError::invalid_argument(
            "md5",
            format!("session is not ready for analysis: {md5}"),
        )
        .into());
    }
    let job = state.insert_job(job_kind::START_ANALYSIS, Some(md5.clone()));
    let task_state = state.clone();
    let job_id = job.id.clone();
    tokio::spawn(async move {
        let outcome = run(&task_state, &md5, &job_id, Value::Object(params)).await;
        task_state.finish_job(
            &job_id,
            outcome.map_err(|err| DomainError::from_error(&err)),
        );
    });
    state.await_job(&job.id, wait).await
}

/// Starts the analysis. Then it asks `analysis.get` for the status until the
/// analysis completes, fails, cancels or stays idle.
async fn run(state: &Arc<McpState>, md5: &str, job_id: &str, params: Value) -> Result<Value> {
    let initial = session::call(state, md5, "analysis.start", params).await?;
    let initial_snapshot = rpc_result(initial)?;
    record_progress(state, job_id, &initial_snapshot);
    if let Some(terminal) = check_terminal_status(&initial_snapshot)? {
        return Ok(terminal);
    }

    let mut consecutive_errors = 0usize;
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        let poll_result = session::call(state, md5, "analysis.get", json!({})).await;
        let response = match poll_result {
            Ok(resp) => resp,
            Err(err) => {
                consecutive_errors += 1;
                if is_session_terminal(state, md5)
                    || consecutive_errors >= MAX_CONSECUTIVE_POLL_FAILURES
                {
                    return Err(err.context("analysis polling failed"));
                }
                let current_progress = state.job(job_id).ok().and_then(|job| job.progress);
                state.set_job_progress(job_id, current_progress, Some(err.to_string()));
                continue;
            }
        };

        let snapshot = match rpc_result(response) {
            Ok(snapshot) => {
                consecutive_errors = 0;
                record_progress(state, job_id, &snapshot);
                snapshot
            }
            Err(err) => {
                consecutive_errors += 1;
                if is_session_terminal(state, md5)
                    || consecutive_errors >= MAX_CONSECUTIVE_POLL_FAILURES
                {
                    return Err(err.context("analysis polling failed"));
                }
                let current_progress = state.job(job_id).ok().and_then(|job| job.progress);
                state.set_job_progress(job_id, current_progress, Some(err.to_string()));
                continue;
            }
        };

        if let Some(terminal) = check_terminal_status(&snapshot)? {
            return Ok(terminal);
        }
    }
}

/// Returns the completion outcome if the snapshot represents a finished analysis.
fn check_terminal_status(snapshot: &Value) -> Result<Option<Value>> {
    match snapshot.get("status").and_then(Value::as_str) {
        Some("completed") => Ok(Some(json!({ "analysis": snapshot }))),
        Some("failed") => {
            let reason = snapshot
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("analysis failed")
                .to_string();
            Err(DomainError::transaction_failed(reason).into())
        }
        Some("cancelled") => Err(DomainError::Internal {
            message: "analysis cancelled".to_string(),
        }
        .into()),
        Some("idle") => Err(DomainError::Internal {
            message: "analysis did not start".to_string(),
        }
        .into()),
        _ => Ok(None),
    }
}

/// Returns `true` after the session closes, stops, or has a fatal error.
fn is_session_terminal(state: &McpState, md5: &str) -> bool {
    state
        .session(md5)
        .is_ok_and(|session| session.status.is_terminal())
}

/// Copies the progress fields of a bridge `analysis.*` snapshot to the job.
fn record_progress(state: &McpState, job_id: &str, snapshot: &Value) {
    let progress: Map<String, Value> = [
        "progress",
        "started_at",
        "finished_at",
        "task_id",
        "analyzed",
    ]
    .into_iter()
    .filter_map(|key| Some((key.to_string(), snapshot.get(key)?.clone())))
    .collect();
    let error = snapshot
        .get("error")
        .and_then(Value::as_str)
        .filter(|error| !error.is_empty())
        .map(str::to_string);
    state.set_job_progress(
        job_id,
        (!progress.is_empty()).then_some(Value::Object(progress)),
        error,
    );
}

/// Returns the result of a bridge response. If the response is an error, the
/// function returns its message as an error.
fn rpc_result(envelope: RpcEnvelope) -> Result<Value> {
    if let Some(error) = envelope.error {
        return Err(DomainError::from_bridge(envelope.status, &error).into());
    }
    envelope.result.ok_or_else(|| {
        DomainError::Internal {
            message: "bridge response missing result".to_string(),
        }
        .into()
    })
}
