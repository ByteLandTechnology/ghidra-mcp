// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The local operations: the operations that the daemon runs, not the bridge.
//!
//! To add a local operation, add one entry to [`LOCAL_OPERATIONS`].

use super::catalog::{Effects, Md5Rule};
use super::{parse, Daemon, Handler, Output, Request};
use crate::error::DomainError;
use crate::model::{JobStatus, SessionRecord};
use crate::{analysis, session};
use anyhow::Result;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::time::Duration;

/// An operation that the daemon runs.
pub(super) struct LocalOperation {
    /// The domain of the operation.
    pub domain: &'static str,
    /// The operation name in the domain.
    pub name: &'static str,
    /// The description that `ghidra_help` shows.
    pub description: &'static str,
    /// The JSON Schema of `params`. For [`Basis::Extends`], the schema adds
    /// its properties to the schema of the bridge method.
    pub schema: fn() -> Value,
    /// The rule for the `md5` argument.
    pub md5: Md5Rule,
    /// The source of the effects of the operation.
    pub basis: Basis,
    /// Runs the operation.
    pub run: Handler,
}

/// The source of the effects of a local operation.
pub(super) enum Basis {
    /// The daemon runs the operation alone. It has these effects.
    Own(Effects),
    /// The operation runs this bridge method with lifecycle behavior around
    /// it. It gets the parameters and the effects of the method.
    Extends(&'static str),
}

impl LocalOperation {
    /// Returns the bridge method that the operation extends, if any.
    pub fn extended_method(&self) -> Option<&'static str> {
        match self.basis {
            Basis::Own(_) => None,
            Basis::Extends(method) => Some(method),
        }
    }
}

/// The effects of an operation that reads the daemon state.
const READ: Effects = Effects {
    read_only: true,
    mutates_program: false,
    destructive: false,
    idempotent: true,
    allowed_during_analysis: true,
    requires_transaction: false,
};

/// Returns the schema of `params` without parameters.
fn no_params() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

/// All local operations, in the sequence of `ghidra_help`.
pub(super) const LOCAL_OPERATIONS: &[LocalOperation] = &[
    LocalOperation {
        domain: "session",
        name: "open",
        description: concat!(
            "Open or reuse a binary session without auto-analysis. Set md5 to load an active ",
            "or saved project, or params.path to import a daemon-local file. Returns at once ",
            "by default. Set wait=true to wait until ready. Upload remote files with ",
            "ghidra_upload prepare."
        ),
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" },
                    "wait": { "type": "boolean", "default": false },
                    "timeoutMs": { "type": "integer", "minimum": 1 }
                },
                "additionalProperties": false
            })
        },
        md5: Md5Rule::Optional,
        // An open with `path` imports the binary into a new Ghidra program.
        basis: Basis::Own(Effects {
            read_only: false,
            mutates_program: true,
            destructive: false,
            idempotent: true,
            allowed_during_analysis: true,
            requires_transaction: false,
        }),
        run: |daemon, request| Box::pin(open_session(daemon, request)),
    },
    LocalOperation {
        domain: "session",
        name: "list",
        description: concat!(
            "List session summaries by MD5 without exposing binary paths. You do not need to ",
            "list sessions before you open one."
        ),
        schema: no_params,
        md5: Md5Rule::Absent,
        basis: Basis::Own(READ),
        run: |daemon, _| {
            Box::pin(async move {
                let sessions: Vec<Value> = daemon
                    .state
                    .sessions()
                    .iter()
                    .map(SessionRecord::summary)
                    .collect();
                Ok((
                    format!("Found {} session(s)", sessions.len()),
                    json!({ "sessions": sessions }),
                ))
            })
        },
    },
    LocalOperation {
        domain: "session",
        name: "get",
        description: "Get one session summary by MD5.",
        schema: no_params,
        md5: Md5Rule::Required,
        basis: Basis::Own(READ),
        run: |daemon, request| {
            Box::pin(async move {
                let md5 = request.session();
                let session = daemon.state.session(&md5)?;
                Ok((
                    format!("Fetched session {md5}"),
                    json!({ "session": session.summary() }),
                ))
            })
        },
    },
    LocalOperation {
        domain: "session",
        name: "close",
        description: "Close an active session.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "force": { "type": "boolean", "default": false }
                },
                "additionalProperties": false
            })
        },
        md5: Md5Rule::Required,
        basis: Basis::Own(Effects {
            read_only: false,
            mutates_program: true,
            destructive: true,
            idempotent: false,
            allowed_during_analysis: true,
            requires_transaction: false,
        }),
        run: |daemon, request| {
            Box::pin(async move {
                let md5 = request.session();
                let CloseArgs { force } = parse(&request.label, request.params)?;
                session::close(&daemon.state, &md5, force).await?;
                let session = daemon.state.session(&md5)?;
                Ok((
                    format!("Closed session {md5}"),
                    json!({ "session": session.summary() }),
                ))
            })
        },
    },
    LocalOperation {
        domain: "upload",
        name: "prepare",
        description: concat!(
            "Prepare a single-use HTTP upload for a remote binary. Returns a POST URL, headers, ",
            "and an expiration time. HTTP calls return an absolute URL from request headers. ",
            "Other transports return a URL relative to the MCP URL. Stream raw bytes there. A ",
            "valid upload opens or reuses the MD5 session."
        ),
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "fileName": { "type": "string", "minLength": 1 },
                    "size": { "type": "integer", "minimum": 1 }
                },
                "required": ["fileName", "size"],
                "additionalProperties": false
            })
        },
        md5: Md5Rule::Required,
        basis: Basis::Own(Effects {
            read_only: false,
            mutates_program: false,
            destructive: false,
            idempotent: false,
            allowed_during_analysis: true,
            requires_transaction: false,
        }),
        run: |daemon, request| {
            Box::pin(async move {
                let md5 = request.session();
                let args = parse(&request.label, request.params)?;
                daemon.uploads.prepare(md5, args)
            })
        },
    },
    LocalOperation {
        domain: "job",
        name: "get",
        description: "Get one background job by ID.",
        schema: || {
            json!({
                "type": "object",
                "properties": { "jobId": { "type": "string" } },
                "required": ["jobId"],
                "additionalProperties": false
            })
        },
        md5: Md5Rule::Absent,
        basis: Basis::Own(READ),
        run: |daemon, request| {
            Box::pin(async move {
                let JobArgs { job_id, .. } = parse(&request.label, request.params)?;
                let job = daemon.state.job(&job_id)?;
                Ok((format!("Fetched job {job_id}"), json!({ "job": job })))
            })
        },
    },
    LocalOperation {
        domain: "job",
        name: "wait",
        description: "Wait for a background job to finish.",
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "jobId": { "type": "string" },
                    "timeoutMs": { "type": "integer", "minimum": 1 }
                },
                "required": ["jobId"],
                "additionalProperties": false
            })
        },
        md5: Md5Rule::Absent,
        basis: Basis::Own(READ),
        run: |daemon, request| {
            Box::pin(async move {
                let JobArgs { job_id, timeout_ms } = parse(&request.label, request.params)?;
                let timeout = millis_or(timeout_ms, daemon.state.config.launch_timeout());
                let job = daemon.state.await_job(&job_id, Some(timeout)).await?;
                Ok((format!("Job {job_id} finished"), json!({ "job": job })))
            })
        },
    },
    LocalOperation {
        domain: "analysis",
        name: "start",
        description: concat!(
            "Start auto-analysis for a current ready session. Returns at once by default. ",
            "Set wait=true to block until analysis completes."
        ),
        schema: || {
            json!({
                "type": "object",
                "properties": {
                    "wait": { "type": "boolean", "default": false },
                    "timeoutMs": { "type": "integer", "minimum": 1 }
                }
            })
        },
        md5: Md5Rule::Required,
        basis: Basis::Extends("analysis.start"),
        run: |daemon, request| Box::pin(start_analysis(daemon, request)),
    },
];

/// Returns the `timeoutMs` parameter, or `default` if it has no value.
fn millis_or(millis: Option<u64>, default: Duration) -> Duration {
    millis.map_or(default, Duration::from_millis)
}

/// The parameters of `ghidra_session open`. The call has `path` or `md5`, not both.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenArgs {
    /// A file on the daemon host.
    path: Option<String>,
    /// Wait until the session is ready.
    #[serde(default)]
    wait: bool,
    /// The maximum wait, instead of the launch timeout.
    timeout_ms: Option<u64>,
}

/// The parameters of `ghidra_analysis start`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AnalysisArgs {
    /// Wait until the analysis ends.
    #[serde(default)]
    wait: bool,
    /// The maximum wait, instead of the import timeout.
    timeout_ms: Option<u64>,
    /// The other parameters. The daemon sends them to `analysis.start` of the bridge.
    #[serde(flatten)]
    params: Map<String, Value>,
}

/// The parameters of `ghidra_session close`.
#[derive(Deserialize)]
struct CloseArgs {
    /// Kill the process. Do not tell the bridge to save and stop.
    #[serde(default)]
    force: bool,
}

/// The parameters of `ghidra_job get` and `ghidra_job wait`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JobArgs {
    /// The job.
    job_id: String,
    /// The maximum wait of `ghidra_job wait`, instead of the launch timeout.
    timeout_ms: Option<u64>,
}

/// Runs `ghidra_session open`: imports a file on the daemon host, or opens a saved binary.
async fn open_session(daemon: &Daemon, request: Request) -> Result<Output> {
    let args: OpenArgs = parse(&request.label, request.params)?;
    let state = &daemon.state;
    let wait = args
        .wait
        .then(|| millis_or(args.timeout_ms, state.config.launch_timeout()));
    match (args.path, request.md5) {
        (Some(path), None) => {
            let raw = PathBuf::from(path);
            let path = raw.canonicalize().map_err(|err| {
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
            let path_buf = path.clone();
            let md5 = tokio::task::spawn_blocking(move || crate::ghidra::file_md5(&path_buf))
                .await
                .map_err(|err| DomainError::Internal {
                    message: format!("file_md5 task panicked: {err}"),
                })??;
            session::open(state, md5, Some(&path), wait).await
        }
        (None, Some(md5)) => session::open(state, md5, None, wait).await,
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

/// Runs `ghidra_analysis start`.
async fn start_analysis(daemon: &Daemon, request: Request) -> Result<Output> {
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
