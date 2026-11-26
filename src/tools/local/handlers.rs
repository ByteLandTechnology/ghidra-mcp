// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Execution handlers for multi-step local operations in [`super::LOCAL_OPERATIONS`].

use super::{
    millis_or, parse, AnalysisArgs, AttachArgs, Daemon, OpenArgs, Output, Request, ShutdownArgs,
};
use crate::error::DomainError;
use crate::import::{is_gpr_path, OpenOptions};
use crate::model::{JobStatus, SessionRecord};
use crate::{analysis, session};
use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Returns the MD5 of each live session and the ID of each job that runs.
fn live_work(daemon: &Daemon) -> (Vec<String>, Vec<String>) {
    let mut sessions: Vec<String> = daemon
        .state
        .sessions()
        .into_iter()
        .filter(|session| session.status.is_live())
        .map(|session| session.session_id)
        .collect();
    let mut jobs: Vec<String> = daemon
        .state
        .jobs()
        .into_iter()
        .filter(|job| job.status == JobStatus::Running)
        .map(|job| job.id)
        .collect();
    sessions.sort();
    jobs.sort();
    (sessions, jobs)
}

/// Runs `ghidra_daemon status`.
pub(super) fn daemon_status(daemon: &Daemon) -> Output {
    let control = &daemon.control;
    let started = control
        .started_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let uptime = control.started_at.elapsed().unwrap_or_default();
    let sessions: Vec<Value> = daemon
        .state
        .sessions()
        .iter()
        .map(SessionRecord::summary)
        .collect();
    let jobs: Vec<_> = daemon
        .state
        .jobs()
        .into_iter()
        .filter(|job| job.status == JobStatus::Running)
        .collect();
    let pid = std::process::id();
    (
        format!("Daemon {pid} runs with {} session(s)", sessions.len()),
        json!({
            "daemon": {
                "pid": pid,
                "version": env!("CARGO_PKG_VERSION"),
                "startedAt": started.as_secs(),
                "uptimeSeconds": uptime.as_secs(),
                "mcpUrl": control.mcp_url,
            },
            "sessions": sessions,
            "jobs": jobs,
        }),
    )
}

/// The time between the reply of `ghidra_daemon shutdown` and the start of the shutdown.
/// Then the reply gets to the client before the daemon closes the connections.
const SHUTDOWN_DELAY: Duration = Duration::from_millis(200);

/// Runs `ghidra_daemon shutdown`.
pub(super) fn shutdown_daemon(daemon: &Daemon, request: Request) -> Result<Output> {
    let ShutdownArgs { force } = parse(&request.label, request.params)?;
    let (sessions, jobs) = live_work(daemon);
    if !force && (!sessions.is_empty() || !jobs.is_empty()) {
        return Err(DomainError::invalid_argument(
            "force",
            format!(
                "the daemon has {} live session(s) {sessions:?} and {} running job(s) {jobs:?}; \
                 set force=true to stop it",
                sessions.len(),
                jobs.len()
            ),
        )
        .into());
    }
    let shutdown = daemon.control.shutdown.clone();
    tokio::spawn(async move {
        tokio::time::sleep(SHUTDOWN_DELAY).await;
        shutdown.cancel();
    });
    Ok((
        "The daemon is shutting down".to_string(),
        json!({ "shuttingDown": true, "sessions": sessions, "jobs": jobs }),
    ))
}

/// Runs `ghidra_session open`: imports a binary, attaches a `.gpr` project, or reopens an MD5.
pub(super) async fn open_session(daemon: &Daemon, request: Request) -> Result<Output> {
    let args: OpenArgs = parse(&request.label, request.params)?;
    let options = OpenOptions::from_raw(
        args.processor.as_deref(),
        args.compiler_spec.as_deref(),
        args.loader.as_deref(),
        args.base_address.as_deref(),
        args.reimport,
        args.program_name.as_deref(),
    )?;
    let state = &daemon.state;
    let wait = args
        .wait
        .then(|| millis_or(args.timeout_ms, state.config.launch_timeout()));
    match (args.path, request.md5) {
        (Some(path), None) => {
            let raw = PathBuf::from(path);
            options.validate_for_target(is_gpr_path(&raw))?;
            session::open_with_options(state, None, Some(&raw), options, wait).await
        }
        (None, Some(md5)) => {
            session::open_with_options(state, Some(md5), None, options, wait).await
        }
        (None, None) => Err(DomainError::invalid_argument(
            "path/md5",
            "`ghidra_session open` requires either params.path or md5",
        )
        .into()),
        (Some(_), Some(_)) => Err(DomainError::invalid_argument(
            "path/md5",
            "`ghidra_session open` accepts either params.path or md5, not both",
        )
        .into()),
    }
}

/// Runs `ghidra_session attach`: connects to a loopback `Bridge.java` endpoint or issues arguments.
pub(super) async fn attach_session(daemon: &Daemon, request: Request) -> Result<Output> {
    let args: AttachArgs = parse(&request.label, request.params)?;
    let state = &daemon.state;
    let endpoint_url = match (args.ws_url, args.port) {
        (Some(_), Some(_)) => {
            return Err(DomainError::invalid_argument(
                "wsUrl/port",
                "`ghidra_session attach` accepts either params.wsUrl or params.port, not both",
            )
            .into());
        }
        (Some(url), None) => Some(url),
        (None, Some(port)) => Some(crate::bridge::gui_ws_url_for_port(port)?),
        (None, None) => None,
    };
    if endpoint_url.is_none() && args.token.is_some() {
        return Err(DomainError::invalid_argument(
            "token",
            "`params.token` requires `params.wsUrl` or `params.port`",
        )
        .into());
    }
    let (md5, file_name) = resolve_attach_identity(args.path, request.md5, args.file_name).await?;
    if let Some(ws_url) = endpoint_url {
        let timeout = millis_or(args.timeout_ms, state.config.launch_timeout());
        return session::attach_endpoint(
            state,
            md5,
            file_name,
            &ws_url,
            args.token.as_deref(),
            timeout,
        )
        .await;
    }
    let wait = args
        .wait
        .then(|| millis_or(args.timeout_ms, state.config.launch_timeout()));
    session::attach(state, md5, file_name, wait).await
}

/// Resolves the `(md5, file_name)` pair for `ghidra_session attach`.
async fn resolve_attach_identity(
    path: Option<String>,
    md5: Option<String>,
    file_name: Option<String>,
) -> Result<(String, Option<String>)> {
    match (path, md5) {
        (Some(_), Some(_)) => Err(DomainError::invalid_argument(
            "path/md5",
            "`ghidra_session attach` accepts either params.path or md5, not both",
        )
        .into()),
        (Some(raw), None) => {
            let path = PathBuf::from(raw).canonicalize().map_err(|err| {
                DomainError::missing_target(
                    "path",
                    format!("target path cannot be resolved: {err}"),
                )
            })?;
            if !path.is_file() {
                return Err(
                    DomainError::missing_target("path", "target path is not a file").into(),
                );
            }
            let inferred_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    DomainError::invalid_argument("path", "binary filename must be valid UTF-8")
                })?
                .to_string();
            let md5 = tokio::task::spawn_blocking(move || crate::ghidra::file_md5(&path))
                .await
                .map_err(|err| DomainError::Internal {
                    message: format!("file_md5 task panicked: {err}"),
                })??;
            Ok((md5, Some(file_name.unwrap_or(inferred_name))))
        }
        (None, Some(md5)) => Ok((md5, file_name)),
        (None, None) => Ok((uuid::Uuid::new_v4().simple().to_string(), file_name)),
    }
}

/// Runs `ghidra_analysis start`.
pub(super) async fn start_analysis(daemon: &Daemon, request: Request) -> Result<Output> {
    let md5 = request.session();
    let args: AnalysisArgs = parse(&request.label, request.params)?;
    let state = &daemon.state;
    let wait = args
        .wait
        .then(|| millis_or(args.timeout_ms, state.config.timeouts.analysis_import));
    let job = analysis::start(state, md5.clone(), args.params, wait).await?;
    let text = if wait.is_some() && job.status == JobStatus::Completed {
        format!("Analysis completed for session {md5}")
    } else {
        format!("Analysis started for session {md5}")
    };
    Ok((text, json!({ "job": job })))
}
