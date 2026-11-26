// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! GUI session attachment: direct loopback endpoints and outbound credentials.

use crate::bridge;
use crate::error::DomainError;
use crate::model::{job_kind, SessionRecord};
use crate::project::{generate_agent_token, normalize_md5, validate_file_name};
use crate::state::McpState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

/// Default display name for an attached GUI session before `ghidra.ready` arrives.
pub const DEFAULT_ATTACHED_NAME: &str = "attached-program";

/// Issues outbound `Bridge.java` connection arguments for an open GUI binary without file copies.
///
/// # Errors
///
/// Fails during daemon shutdown, when `md5` or `file_name` is invalid, or when the wait fails.
pub async fn attach(
    state: &Arc<McpState>,
    md5: String,
    file_name: Option<String>,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    if state.is_shutting_down() {
        return Err(DomainError::ShuttingDown.into());
    }
    let md5 = normalize_md5(&md5)?;
    if let Some(ref name) = file_name {
        validate_file_name(name)?;
    }
    let (token, job_id) = {
        let _guard = state.lifecycle_lock(&md5)?.lock_owned().await;
        if state.is_shutting_down() {
            return Err(DomainError::ShuttingDown.into());
        }
        let resolved_name = file_name
            .or_else(|| state.find_session(&md5).map(|existing| existing.file_name))
            .unwrap_or_else(|| DEFAULT_ATTACHED_NAME.to_string());
        state.detach_bridge(&md5, "session attach issued a new credential");
        state.stop_process(&md5, Duration::ZERO).await;
        state.fail_session_jobs(&md5, &DomainError::disconnected(&md5));
        let token = generate_agent_token();
        let record = SessionRecord::attaching(md5.clone(), resolved_name, token.clone());
        state.put_session(&record)?;
        let job = state.insert_job(job_kind::ATTACH_SESSION, Some(md5.clone()));
        state.set_launch_job(&md5, Some(job.id.clone()));
        (token, job.id)
    };
    let ws_url = state.bridge_ws_url.clone();
    let bridge_args = format!("ws_url={ws_url} session_id={md5} token={token}");
    let job = state.await_job(&job_id, wait).await?;
    let session = state.session(&md5)?;
    let text = if session.ws_connected {
        format!("Attached session {md5} is ready")
    } else {
        format!("Issued Bridge.java attach arguments for session {md5}")
    };
    Ok((
        text,
        json!({
            "md5": md5,
            "wsUrl": ws_url,
            "sessionId": md5,
            "token": token,
            "bridgeArgs": bridge_args,
            "session": session.summary(),
            "jobId": job_id,
            "job": job,
        }),
    ))
}

/// Connects directly to a loopback GUI `Bridge.java` WebSocket listener without file copies.
///
/// # Errors
///
/// Fails if `md5`, `file_name`, `ws_url`, or `bearer_token` is invalid, or if the handshake fails.
pub async fn attach_endpoint(
    state: &Arc<McpState>,
    md5: String,
    file_name: Option<String>,
    ws_url: &str,
    bearer_token: Option<&str>,
    timeout: Duration,
) -> Result<(String, Value)> {
    if state.is_shutting_down() {
        return Err(DomainError::ShuttingDown.into());
    }
    let md5 = normalize_md5(&md5)?;
    if let Some(ref name) = file_name {
        validate_file_name(name)?;
    }
    let endpoint = bridge::parse_gui_ws_url(ws_url)?;
    let bearer = bridge::validate_bearer_token(bearer_token)?;
    let (session_token, job_id) = {
        let _guard = state.lifecycle_lock(&md5)?.lock_owned().await;
        if state.is_shutting_down() {
            return Err(DomainError::ShuttingDown.into());
        }
        let resolved_name = file_name
            .or_else(|| state.find_session(&md5).map(|existing| existing.file_name))
            .unwrap_or_else(|| DEFAULT_ATTACHED_NAME.to_string());
        state.detach_bridge(&md5, "session attach replaced the bridge connection");
        state.stop_process(&md5, Duration::ZERO).await;
        state.fail_session_jobs(&md5, &DomainError::disconnected(&md5));
        let token = generate_agent_token();
        let record = SessionRecord::attaching(md5.clone(), resolved_name, token.clone());
        state.put_session(&record)?;
        let job = state.insert_job(job_kind::ATTACH_SESSION, Some(md5.clone()));
        state.set_launch_job(&md5, Some(job.id.clone()));
        (token, job.id)
    };
    let connected = match bridge::connect_gui_endpoint(
        state.clone(),
        &md5,
        &session_token,
        endpoint,
        bearer.as_deref(),
        timeout,
    )
    .await
    {
        Ok(connected) => connected,
        Err(err) => {
            crate::process::record_daemon_error(&format!("session {md5} attach failed: {err:#}"));
            let domain = DomainError::from_error(&err);
            state.fail_launch(&md5, &job_id, domain.clone()).await;
            return Err(domain.into());
        }
    };
    let job = state.job(&job_id)?;
    let session = state.session(&md5)?;
    Ok((
        format!("Attached session {md5} to {}", connected.display_url),
        json!({
            "md5": md5,
            "wsUrl": connected.display_url,
            "sessionId": md5,
            "bridgeSessionId": connected.bridge_session_id,
            "session": session.summary(),
            "jobId": job_id,
            "job": job,
        }),
    ))
}
