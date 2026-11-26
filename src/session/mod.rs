// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The session lifecycle: open a session, launch Ghidra, wait for its bridge,
//! relaunch the bridge, call bridge methods, and close the session.
//!
//! A launch has these steps. Each step has the lifecycle lock of its MD5:
//!
//! 1. [`begin_launch`] prepares the project and stops the previous process. It
//!    saves a `launching` record with a new bridge credential. It also makes
//!    the launch job. From this point, the job owns the session.
//! 2. [`launch_process`] starts `analyzeHeadless` with the bridge as its
//!    post-script, and sets the session to `starting`.
//! 3. The bridge connects and completes its handshake (see [`crate::bridge`]).
//!    This sets the session to `ready`.
//! 4. [`wait_ready`] sees `ready` and completes the job. It fails the job when
//!    the process stops too early or the launch takes too long.
//!
//! Each step first makes sure that its job or its credential still owns the
//! session. A newer launch can replace a launch, and a client can close a
//! session. In these conditions, the old step stops and does not change the newer state.

use crate::bridge;
use crate::error::DomainError;
use crate::import::{hex_encode, is_gpr_path, OpenOptions};
use crate::java_path::java_path;
use crate::model::{job_kind, JobRecord, JobStatus, RpcEnvelope, SessionRecord, SessionStatus};
use crate::process::{append_java_tool_option, spawn_log_forwarder, ManagedChild};
use crate::project::{
    attached_program_name, check_gpr_not_locked, is_attached_gpr_session, is_reimport_pending,
    normalize_md5, persist_attached_gpr, persist_binary_with_options, prepare_project,
    reset_binary_ghidra_project, resolve_gpr_path, sanitize_text_paths,
    update_attached_program_name, update_binary_import_options, LaunchMode, PreparedProject,
    ResolvedGpr,
};
use crate::state::McpState;
use anyhow::Result;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OwnedMutexGuard;
use tokio::time::Instant;

mod checkpoints;

pub use checkpoints::{checkpoint_create, checkpoint_list, checkpoint_restore, delete, reset};

/// The time that Ghidra has to exit after its bridge session ends. After this time,
/// the bridge halts the JVM, but never during a save. Then no orphan Ghidra
/// process stays when the daemon stops without a chance to stop it.
const GHIDRA_EXIT_DEADLINE: Duration = Duration::from_mins(2);

/// Marker prefix emitted by `OpenSavedProject.java` and `ImportBinary.java` on open errors.
const OPEN_ERROR_MARKER: &str = "GHIDRA_MCP_OPEN_ERROR: ";

/// Opens or reuses a session by `md5` with default options.
#[cfg(test)]
pub async fn open(
    state: &Arc<McpState>,
    md5: String,
    input: Option<&Path>,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    let md5 = normalize_md5(&md5)?;
    if let Some(path) = input {
        return open_with_options(state, None, Some(path), OpenOptions::default(), wait).await;
    }
    open_with_options(state, Some(md5), None, OpenOptions::default(), wait).await
}

/// Opens a local binary or `.gpr` project, or reopens a saved session by `md5`.
pub async fn open_with_options(
    state: &Arc<McpState>,
    md5: Option<String>,
    input: Option<&Path>,
    options: OpenOptions,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    if state.is_shutting_down() {
        return Err(DomainError::ShuttingDown.into());
    }
    match (input, md5) {
        (Some(path), None) => open_by_path(state, path, &options, wait).await,
        (None, Some(raw_md5)) => open_by_md5(state, &raw_md5, &options, wait).await,
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

/// Opens or reuses a session from a local binary or `.gpr` path.
async fn open_by_path(
    state: &Arc<McpState>,
    path: &Path,
    options: &OpenOptions,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    if is_gpr_path(path) {
        options.validate_for_target(true)?;
        let source = path.to_path_buf();
        let gpr = tokio::task::spawn_blocking(move || resolve_gpr_path(&source))
            .await
            .map_err(|err| DomainError::Internal {
                message: format!("project path task failed: {err}"),
            })??;
        let md5 = gpr.md5.clone();
        let guard = state.lifecycle_lock(&md5)?.lock_owned().await;
        if state.is_shutting_down() {
            return Err(DomainError::ShuttingDown.into());
        }
        let switched = persist_gpr_open(state, gpr, options.program_name.clone()).await?;
        return finish_open(state, md5, false, switched, guard, wait).await;
    }

    let md5 = prepare_binary_open(state, path, options).await?;
    if state.is_shutting_down() {
        return Err(DomainError::ShuttingDown.into());
    }
    if !options.reimport {
        if let Some(output) = try_reuse_ready_session(state, &md5)? {
            return Ok(output);
        }
    }
    let guard = state.lifecycle_lock(&md5)?.lock_owned().await;
    finish_open(state, md5, options.reimport, false, guard, wait).await
}

/// Opens or reuses a session by canonical `md5`.
async fn open_by_md5(
    state: &Arc<McpState>,
    raw_md5: &str,
    options: &OpenOptions,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    let md5 = normalize_md5(raw_md5)?;
    if options.is_empty() {
        if let Some(output) = try_reuse_ready_session(state, &md5)? {
            return Ok(output);
        }
        let guard = state.lifecycle_lock(&md5)?.lock_owned().await;
        return finish_open(state, md5, false, false, guard, wait).await;
    }
    let guard = state.lifecycle_lock(&md5)?.lock_owned().await;
    if state.is_shutting_down() {
        return Err(DomainError::ShuttingDown.into());
    }
    let switched = prepare_md5_open(state, &md5, options).await?;
    finish_open(state, md5, options.reimport, switched, guard, wait).await
}

/// Returns the reuse output when `md5` has a ready connected session and no deferred reimport.
fn try_reuse_ready_session(state: &McpState, md5: &str) -> Result<Option<(String, Value)>> {
    if is_reimport_pending(&state.paths, md5)? {
        return Ok(None);
    }
    Ok(state
        .find_session(md5)
        .filter(|session| session.status == SessionStatus::Ready && session.ws_connected)
        .map(|session| reused_session_output(md5, &session)))
}

/// Checks `.gpr` lock ownership and saves `attached.json` under the MD5 lifecycle lock.
async fn persist_gpr_open(
    state: &Arc<McpState>,
    gpr: ResolvedGpr,
    requested_program: Option<String>,
) -> Result<bool> {
    let paths = state.paths.clone();
    let state_ref = state.clone();
    tokio::task::spawn_blocking(move || -> Result<bool> {
        let current = state_ref.find_session(&gpr.md5);
        let daemon_owns = current
            .as_ref()
            .is_some_and(|session| session.ws_connected || session.status.is_launching());
        if !daemon_owns {
            check_gpr_not_locked(&gpr)?;
        }
        let prev_program = attached_program_name(&paths, &gpr.md5)?;
        let switched = requested_program
            .as_ref()
            .is_some_and(|wanted| prev_program.as_ref() != Some(wanted));
        persist_attached_gpr(&paths, &gpr, requested_program.as_deref())?;
        Ok(switched)
    })
    .await
    .map_err(|err| DomainError::Internal {
        message: format!("project attachment task failed: {err}"),
    })?
}

/// Checks and saves a local binary file and its import flags.
async fn prepare_binary_open(
    state: &Arc<McpState>,
    path: &Path,
    options: &OpenOptions,
) -> Result<String> {
    options.validate_for_target(false)?;
    let canonical = path.canonicalize().map_err(|err| {
        DomainError::missing_target("path", format!("target path cannot be resolved: {err}"))
    })?;
    if !canonical.is_file() {
        return Err(DomainError::missing_target("path", "target path is not a file").into());
    }
    let file_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            DomainError::invalid_argument("path", "binary filename must be valid UTF-8")
        })?
        .to_string();
    let paths = state.paths.clone();
    let import_opts = options.import.clone();
    let reimport = options.reimport;
    tokio::task::spawn_blocking(move || -> Result<String> {
        let computed = crate::ghidra::file_md5(&canonical)?;
        persist_binary_with_options(
            &paths,
            &canonical,
            &computed,
            &file_name,
            &import_opts,
            reimport,
        )?;
        Ok(computed)
    })
    .await
    .map_err(|err| DomainError::Internal {
        message: format!("binary persistence task failed: {err}"),
    })?
}

/// Checks and updates metadata for an `md5` session open with explicit options.
async fn prepare_md5_open(state: &Arc<McpState>, md5: &str, options: &OpenOptions) -> Result<bool> {
    let paths = state.paths.clone();
    let state_ref = state.clone();
    let opts = options.clone();
    let md5_clone = md5.to_string();
    tokio::task::spawn_blocking(move || -> Result<bool> {
        if is_attached_gpr_session(&paths, &md5_clone)? {
            opts.reject_binary_flags_on_gpr()?;
            let current = state_ref.find_session(&md5_clone);
            let daemon_owns = current
                .as_ref()
                .is_some_and(|item| item.ws_connected || item.status.is_launching());
            let prev = attached_program_name(&paths, &md5_clone)?;
            let switched = opts
                .program_name
                .as_ref()
                .is_some_and(|wanted| prev.as_ref() != Some(wanted));
            update_attached_program_name(
                &paths,
                &md5_clone,
                opts.program_name.as_deref(),
                daemon_owns,
            )?;
            Ok(switched)
        } else {
            opts.validate_for_target(false)?;
            update_binary_import_options(&paths, &md5_clone, &opts.import, opts.reimport)?;
            Ok(false)
        }
    })
    .await
    .map_err(|err| DomainError::Internal {
        message: format!("session metadata task failed: {err}"),
    })?
}

/// Runs the slow-path launch or reuse step for `md5` under its lifecycle lock.
async fn finish_open(
    state: &Arc<McpState>,
    md5: String,
    reimport_requested: bool,
    program_switched: bool,
    guard: OwnedMutexGuard<()>,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    let (created, job_id) = {
        let _guard = guard;
        if state.is_shutting_down() {
            return Err(DomainError::ShuttingDown.into());
        }
        let force_reimport = reimport_requested || is_reimport_pending(&state.paths, &md5)?;
        let force_relaunch = force_reimport || program_switched;
        let current = state.find_session(&md5);

        if force_relaunch {
            let job_id = relaunch_for_options(state, &md5, force_reimport).await?;
            (current.is_none() || force_reimport, job_id)
        } else {
            if let Some(session) = current
                .as_ref()
                .filter(|session| session.status == SessionStatus::Ready && session.ws_connected)
            {
                return Ok(reused_session_output(&md5, session));
            }
            let launching_job = current
                .as_ref()
                .filter(|session| session.status.is_launching())
                .and_then(|_| state.launch_job(&md5));
            // Join a launch that is in progress. Do not start a second launch.
            if let Some(job_id) = launching_job {
                (false, job_id)
            } else {
                let kind = if current.is_some() {
                    job_kind::RECOVER_SESSION_BRIDGE
                } else {
                    job_kind::ANALYZE_BINARY
                };
                let (prepared, job_id) = begin_launch(state, &md5, kind).await?;
                tokio::spawn(launch_and_wait(state.clone(), prepared, job_id.clone()));
                (current.is_none(), job_id)
            }
        }
    };

    let job = state.await_job(&job_id, wait).await?;
    if job.status == JobStatus::Failed {
        return Err(DomainError::Internal {
            message: job
                .error
                .unwrap_or_else(|| "Ghidra launch failed".to_string()),
        }
        .into());
    }
    let session = state.session(&md5)?;
    let text = if session.ws_connected {
        format!("Session {md5} is ready")
    } else {
        format!("Session {md5} launch started")
    };
    Ok((
        text,
        json!({
            "created": created,
            "reused": !created,
            "session": session.summary(),
            "jobId": job_id,
            "job": job
        }),
    ))
}

/// Stops an active process, resets internal project files on `force_reimport`, and starts Ghidra.
async fn relaunch_for_options(
    state: &Arc<McpState>,
    md5: &str,
    force_reimport: bool,
) -> Result<String> {
    stop_for_relaunch(state, md5, !force_reimport).await;
    if force_reimport {
        let paths = state.paths.clone();
        let md5_clone = md5.to_string();
        tokio::task::spawn_blocking(move || reset_binary_ghidra_project(&paths, &md5_clone))
            .await
            .map_err(|err| DomainError::Internal {
                message: format!("project reset task failed: {err}"),
            })??;
    }
    let (prepared, job_id) = begin_launch(state, md5, job_kind::ANALYZE_BINARY).await?;
    tokio::spawn(launch_and_wait(state.clone(), prepared, job_id.clone()));
    Ok(job_id)
}

/// Stops an active process for `md5`. The caller must hold `lifecycle_lock`.
async fn stop_for_relaunch(state: &McpState, md5: &str, save_first: bool) {
    if save_first
        && state
            .find_session(md5)
            .is_some_and(|item| item.ws_connected)
    {
        let _ = bridge::request(
            state,
            md5,
            "session.shutdown",
            json!({}),
            Duration::from_secs(5),
        )
        .await;
        state
            .stop_process(md5, state.config.timeouts.bridge_disconnect_grace)
            .await;
    } else {
        state.stop_process(md5, Duration::ZERO).await;
    }
    state.detach_bridge(md5, "session relaunching");
    if let Some(job_id) = state.launch_job(md5) {
        state.fail_job_error(&job_id, DomainError::disconnected(md5));
    }
    state.set_launch_job(md5, None);
}

/// Formats the summary text and JSON payload for a ready session that `open` uses again.
fn reused_session_output(md5: &str, session: &SessionRecord) -> (String, Value) {
    (
        format!("Reused session {md5}"),
        json!({"created": false, "reused": true, "session": session.summary()}),
    )
}

/// Calls a bridge method. First, it connects the bridge of the session, or relaunches it.
pub async fn call(
    state: &Arc<McpState>,
    md5: &str,
    method: &str,
    params: Value,
) -> Result<RpcEnvelope> {
    let md5 = normalize_md5(md5)?;
    ensure_connected(state, &md5).await?;
    let envelope = bridge::request(state, &md5, method, params, state.config.timeouts.rpc).await?;
    if let Some(err) = &envelope.error {
        return Err(DomainError::from_bridge(envelope.status, err).into());
    }
    Ok(envelope)
}

/// Makes sure that the session has a bridge connection.
pub async fn ensure_connected(state: &Arc<McpState>, md5: &str) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    let session = state.session(&md5)?;
    if session.ws_connected {
        return Ok(());
    }
    if session.status.is_launching() {
        return wait_for_launch(state, &md5).await;
    }
    if session.status.is_recoverable() {
        return recover(state, &md5).await;
    }
    Err(DomainError::disconnected(&md5).into())
}

/// Waits for the launch that owns the session. Then the bridge must have a connection.
async fn wait_for_launch(state: &McpState, md5: &str) -> Result<()> {
    let job_id = state
        .launch_job(md5)
        .ok_or_else(|| DomainError::disconnected(md5))?;
    wait_ready(state, md5, &job_id, state.config.launch_timeout()).await?;
    if !state.session(md5)?.ws_connected {
        return Err(DomainError::disconnected(md5).into());
    }
    Ok(())
}

/// Relaunches a disconnected or stale session, and waits until it is ready.
async fn recover(state: &Arc<McpState>, md5: &str) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    let (prepared, job_id) = {
        let guard = state.lifecycle_lock(&md5)?.lock_owned().await;
        if state.is_shutting_down() {
            return Err(DomainError::ShuttingDown.into());
        }
        let current = state.session(&md5)?;
        if current.ws_connected {
            return Ok(());
        }
        if current.status.is_launching() {
            drop(guard);
            return wait_for_launch(state, &md5).await;
        }
        if !current.status.is_recoverable() {
            return Err(DomainError::disconnected(&md5).into());
        }
        begin_launch(state, &md5, job_kind::RECOVER_SESSION_BRIDGE).await?
    };
    launch_and_wait(state.clone(), prepared, job_id).await
}

/// Replaces a session with a new launch and its job. The caller must have the lifecycle lock.
async fn begin_launch(
    state: &McpState,
    md5: &str,
    kind: &'static str,
) -> Result<(PreparedProject, String)> {
    // Stop any previous JVM first so an attached .gpr project releases its own lock.
    state.detach_bridge(md5, "bridge restarting");
    state.stop_process(md5, Duration::ZERO).await;
    let paths = state.paths.clone();
    let binary_md5 = md5.to_string();
    let prepared = tokio::task::spawn_blocking(move || prepare_project(&paths, &binary_md5))
        .await
        .map_err(|err| DomainError::Internal {
            message: format!("project preparation task failed: {err}"),
        })??;
    state.put_session(&prepared.session_record())?;
    let job = state.insert_job(kind, Some(md5.to_string()));
    state.set_launch_job(md5, Some(job.id.clone()));
    Ok((prepared, job.id))
}

/// Starts Ghidra and waits for its bridge. If one of these steps fails, the launch fails.
async fn launch_and_wait(
    state: Arc<McpState>,
    prepared: PreparedProject,
    job_id: String,
) -> Result<()> {
    let md5 = prepared.md5.clone();
    let fresh_import = prepared.is_fresh_binary_import();
    let result = match launch_process(&state, prepared).await {
        Ok(()) => wait_ready(&state, &md5, &job_id, state.config.launch_timeout())
            .await
            .map(drop),
        Err(err) => Err(err),
    };
    if result.is_err() && fresh_import {
        // Remove an empty or partial internal project after a failed initial import.
        let paths = state.paths.clone();
        let md5_cleanup = md5.clone();
        let _ =
            tokio::task::spawn_blocking(move || reset_binary_ghidra_project(&paths, &md5_cleanup))
                .await;
    }
    let outcome = result.map_err(|err| {
        crate::process::record_daemon_error(&format!("session {md5} launch failed: {err:#}"));
        DomainError::from_error(&err)
    });
    if let Err(error) = &outcome {
        state.fail_launch(&md5, &job_id, error.clone()).await;
    }
    outcome.map_err(Into::into)
}

/// Starts Ghidra and records the process.
async fn launch_process(state: &Arc<McpState>, prepared: PreparedProject) -> Result<()> {
    let md5 = normalize_md5(&prepared.md5)?;
    let _guard = state.lifecycle_lock(&md5)?.lock_owned().await;
    if !state
        .session_with_token(&md5, &prepared.agent_token)
        .is_some_and(|session| session.status.is_launching())
    {
        return Err(
            DomainError::missing_target(md5, "binary launch was replaced or closed").into(),
        );
    }
    let task_state = state.clone();
    let child = tokio::time::timeout(
        state.config.timeouts.process_spawn,
        tokio::task::spawn_blocking(move || spawn_ghidra(&task_state, &prepared)),
    )
    .await
    .map_err(|_| DomainError::AgentTimeout {
        md5: md5.clone(),
        timeout_seconds: Some(state.config.timeouts.process_spawn.as_secs()),
    })?
    .map_err(|err| DomainError::Internal {
        message: format!("spawn_ghidra task failed: {err}"),
    })??;
    if let Err(child) = state.register_process(&md5, child) {
        state.reap(child, Duration::ZERO).await;
        return Err(DomainError::ShuttingDown.into());
    }
    state.update_session(&md5, SessionRecord::mark_starting)
}

/// Builds the `analyzeHeadless` command line and starts the process.
fn spawn_ghidra(state: &McpState, prepared: &PreparedProject) -> Result<ManagedChild> {
    state.paths.ensure_layout()?;
    let analyze_headless = java_path(&crate::ghidra::analyze_headless(&state.config)?)?;
    let runtime_dir = &state.paths.runtime_dir;
    let jar = bridge::install_runtime(runtime_dir)?;

    let mut command = Command::new(analyze_headless);
    command
        .arg(java_path(&prepared.ghidra_launch_root)?)
        .arg(&prepared.ghidra_project_name);
    let (script, extra_script_args) = configure_launch_mode(&mut command, &prepared.launch_mode)?;
    command
        .arg("-max-cpu")
        .arg(state.config.analysis.max_cpu.to_string())
        .arg("-scriptPath")
        .arg(java_path(runtime_dir)?)
        .arg("-postScript")
        .arg(script);
    for arg in &extra_script_args {
        command.arg(arg);
    }
    command
        .arg(format!("ws_url={}", state.bridge_ws_url))
        .arg(format!("session_id={}", prepared.md5))
        .arg(format!("token={}", prepared.agent_token))
        .arg(format!(
            "exit_deadline_sec={}",
            GHIDRA_EXIT_DEADLINE.as_secs()
        ))
        .arg(format!("jar={}", java_path(&jar)?.display()));

    if let Some(ghidra_home) = &state.config.ghidra.home {
        let ghidra_home = java_path(Path::new(ghidra_home))?;
        command
            .env("GHIDRA_HOME", &ghidra_home)
            .env("GHIDRA_INSTALL_DIR", &ghidra_home);
    }
    if let Some(java_home) = std::env::var_os("JAVA_HOME") {
        command.env("JAVA_HOME", java_path(Path::new(&java_home))?);
    }
    let java_tmp_option = format!(
        "-Djava.io.tmpdir={}",
        java_path(&state.paths.tmp_dir)?.display()
    );
    command.env(
        "JAVA_TOOL_OPTIONS",
        append_java_tool_option(
            std::env::var("JAVA_TOOL_OPTIONS").ok().as_deref(),
            &java_tmp_option,
        ),
    );
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = ManagedChild::spawn(&mut command).map_err(|err| DomainError::Internal {
        message: format!("spawning analyzeHeadless for ghidra-mcp: {err}"),
    })?;
    if let Some(stdout) = child.take_stdout() {
        let log = state.paths.stdout_log(&prepared.md5);
        spawn_log_forwarder(stdout, log, prepared.agent_token.clone());
    }
    if let Some(stderr) = child.take_stderr() {
        let log = state.paths.stderr_log(&prepared.md5);
        spawn_log_forwarder(stderr, log, prepared.agent_token.clone());
    }
    Ok(child)
}

/// Appends mode-specific flags to `command` and returns `(post_script, extra_script_args)`.
fn configure_launch_mode(
    command: &mut Command,
    launch_mode: &LaunchMode,
) -> Result<(&'static str, Vec<String>)> {
    let mut extra = Vec::new();
    let script = match launch_mode {
        LaunchMode::OpenSaved {
            attached_gpr,
            program_name,
            backup_dir,
        } => {
            command.arg("-noanalysis");
            extra.push(format!("backup_dir={}", java_path(backup_dir)?.display()));
            if *attached_gpr {
                extra.push("attached_gpr=true".to_string());
            }
            if let Some(name) = program_name {
                extra.push(format!("program_name_hex={}", hex_encode(name)));
            }
            bridge::SAVED_PROJECT_SCRIPT_NAME
        }
        LaunchMode::ImportBinary {
            input_path,
            options,
        } => {
            command
                .arg("-import")
                .arg(java_path(input_path)?)
                .args(["-overwrite", "-noanalysis"]);
            if let Some(processor) = &options.processor {
                command.arg("-processor").arg(processor);
            }
            if let Some(compiler_spec) = &options.compiler_spec {
                command.arg("-cspec").arg(compiler_spec);
            }
            if let Some(loader) = options.effective_loader(input_path) {
                command.arg("-loader").arg(loader);
            }
            if let Some(base_address) = &options.base_address {
                command.arg("-loader-baseAddr").arg(base_address);
                extra.push(format!("base_address={base_address}"));
            }
            bridge::IMPORT_BINARY_SCRIPT_NAME
        }
    };
    Ok((script, extra))
}

/// Waits until the bridge is ready, and then completes the launch job.
async fn wait_ready(
    state: &McpState,
    md5: &str,
    job_id: &str,
    timeout: Duration,
) -> Result<JobRecord> {
    let md5 = normalize_md5(md5)?;
    let lifecycle_lock = state.lifecycle_lock(&md5)?;
    let deadline = Instant::now() + timeout;
    loop {
        let guard = lifecycle_lock.lock().await;
        if !state.owns_launch(&md5, job_id) {
            return Err(
                DomainError::missing_target(&md5, "binary launch was replaced or closed").into(),
            );
        }
        let job = state.job(job_id)?;
        match job.status {
            JobStatus::Completed => return Ok(job),
            JobStatus::Failed => {
                return Err(DomainError::Internal {
                    message: job.error.unwrap_or_else(|| "job failed".to_string()),
                }
                .into());
            }
            JobStatus::Running => {}
        }
        let session = state.session(&md5)?;
        if session.status == SessionStatus::Ready {
            state.finish_job(job_id, Ok(json!({ "md5": &md5, "status": session.status })));
            return state.job(job_id);
        }
        if session.status.is_terminal() {
            return Err(DomainError::Internal {
                message: session
                    .last_error
                    .unwrap_or_else(|| format!("session {md5} failed")),
            }
            .into());
        }
        if let Some(status) = state.poll_process_exit(&md5)? {
            drop(guard);
            // Give log forwarder threads a brief moment to flush the final stderr lines.
            tokio::time::sleep(Duration::from_millis(60)).await;
            if let Some(diagnostic) = extract_headless_open_error(state, &md5) {
                return Err(DomainError::invalid_argument("open", diagnostic).into());
            }
            return Err(DomainError::Internal {
                message: format!(
                    "analyzeHeadless exited before ghidra.ready for session {md5} with \
           {status}; inspect logs/{md5}/stdout.log and logs/{md5}/stderr.log"
                ),
            }
            .into());
        }
        if Instant::now() >= deadline {
            let message = format!("timed out waiting for ghidra.ready for session {md5}");
            state.stop_process(&md5, Duration::ZERO).await;
            let _ = state.update_session(&md5, |session| session.mark_error(&message));
            return Err(DomainError::AgentTimeout {
                md5,
                timeout_seconds: Some(timeout.as_secs()),
            }
            .into());
        }
        let notified = state.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        drop(guard);
        let wake = deadline.min(Instant::now() + Duration::from_secs(1));
        let _ = tokio::time::timeout_at(wake, notified).await;
    }
}

/// Extracts a sanitized user-actionable open or import error from session logs.
fn extract_headless_open_error(state: &McpState, md5: &str) -> Option<String> {
    for log_path in [state.paths.stderr_log(md5), state.paths.stdout_log(md5)] {
        let Ok(contents) = fs::read_to_string(log_path) else {
            continue;
        };
        for line in contents.lines().rev() {
            if let Some((_, detail)) = line.split_once(OPEN_ERROR_MARKER) {
                let cleaned = detail.trim().trim_end_matches(" (GhidraScript)").trim();
                return Some(sanitize_text_paths(cleaned));
            }
            if let Some((_, detail)) = line.split_once("InvalidInputException:") {
                let cleaned = detail.trim().trim_end_matches(" (GhidraScript)").trim();
                return Some(sanitize_text_paths(cleaned));
            }
            if line.contains("LockException") || line.contains("Unable to lock project") {
                return Some(
                    "Ghidra project is locked by another process; close it in Ghidra GUI first"
                        .to_string(),
                );
            }
        }
    }
    None
}

/// Closes a session through its bridge. If `force` is `true`, it kills the process.
pub async fn close(state: &McpState, md5: &str, force: bool) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    let _guard = state.lifecycle_lock(&md5)?.lock_owned().await;
    let session = state.session(&md5)?;
    if !force && session.ws_connected {
        let shutdown = bridge::request(
            state,
            &md5,
            "session.shutdown",
            json!({}),
            Duration::from_secs(5),
        );
        let _ = shutdown.await;
        state
            .stop_process(&md5, state.config.timeouts.bridge_disconnect_grace)
            .await;
    } else {
        state.stop_process(&md5, Duration::ZERO).await;
    }
    state.detach_bridge(&md5, "session closed");
    state.update_session(&md5, |session| session.mark_closed(force))?;
    if let Some(job_id) = state.launch_job(&md5) {
        state.fail_job_error(&job_id, DomainError::disconnected(&md5));
    }
    state.set_launch_job(&md5, None);
    Ok(())
}

#[cfg(test)]
mod tests;
