// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The session lifecycle: open a session, launch Ghidra, wait for its bridge,
//! relaunch the bridge, call bridge methods, and close the session.
//!
//! A launch has these steps. Each step has the lifecycle lock:
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
use crate::java_path::java_path;
use crate::model::{job_kind, JobRecord, JobStatus, RpcEnvelope, SessionRecord, SessionStatus};
use crate::process::{append_java_tool_option, spawn_log_forwarder, ManagedChild};
use crate::project::{persist_binary, prepare_project, PreparedProject};
use crate::state::McpState;
use anyhow::Result;
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

/// The time that Ghidra has to exit after its bridge session ends. After this time,
/// the bridge halts the JVM, but never during a save. Then no orphan Ghidra
/// process stays when the daemon stops without a chance to stop it.
const GHIDRA_EXIT_DEADLINE: Duration = Duration::from_mins(2);

/// The name of the Ghidra project in the `ghidra/` directory of each binary.
const GHIDRA_PROJECT_NAME: &str = "project";

/// Opens a saved binary, or imports `input`. If a session for the MD5 exists, it uses that session.
pub async fn open(
  state: &Arc<McpState>,
  md5: String,
  input: Option<&Path>,
  wait: Option<Duration>,
) -> Result<(String, Value)> {
  if state.is_shutting_down() {
    return Err(DomainError::ShuttingDown.into());
  }
  if let Some(path) = input {
    let file_name = path
      .file_name()
      .and_then(|name| name.to_str())
      .ok_or_else(|| DomainError::invalid_argument("path", "binary filename must be valid UTF-8"))?
      .to_string();
    let paths = state.paths.clone();
    let source = path.to_path_buf();
    let md5_clone = md5.clone();
    tokio::task::spawn_blocking(move || persist_binary(&paths, &source, &md5_clone, &file_name))
      .await
      .map_err(|err| DomainError::Internal {
        message: format!("binary persistence task failed: {err}"),
      })??;
  }
  let (created, job_id) = {
    let _guard = state.lifecycle_lock.lock().await;
    if state.is_shutting_down() {
      return Err(DomainError::ShuttingDown.into());
    }
    let existing = state.find_session(&md5);
    if let Some(session) = existing.as_ref().filter(|session| session.ws_connected) {
      return Ok((
        format!("Reused session {md5}"),
        json!({"created": false, "reused": true, "session": session.summary()}),
      ));
    }
    let launching_job = existing
      .as_ref()
      .filter(|session| session.status.is_launching())
      .and_then(|_| state.launch_job(&md5));
    // Join a launch that is in progress. Do not start a second launch.
    if let Some(job_id) = launching_job {
      (false, job_id)
    } else {
      let kind = if existing.is_some() {
        job_kind::RECOVER_SESSION_BRIDGE
      } else {
        job_kind::ANALYZE_BINARY
      };
      let (prepared, job_id) = begin_launch(state, &md5, kind).await?;
      tokio::spawn(launch_and_wait(state.clone(), prepared, job_id.clone()));
      (existing.is_none(), job_id)
    }
  };
  let job = state.await_job(&job_id, wait).await?;
  if job.status == JobStatus::Failed {
    return Err(
      DomainError::Internal {
        message: job
          .error
          .unwrap_or_else(|| "Ghidra launch failed".to_string()),
      }
      .into(),
    );
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

/// Calls a bridge method. First, it connects the bridge of the session, or relaunches it.
pub async fn call(
  state: &Arc<McpState>,
  md5: &str,
  method: &str,
  params: Value,
) -> Result<RpcEnvelope> {
  ensure_connected(state, md5).await?;
  let envelope = bridge::request(state, md5, method, params, state.config.timeouts.rpc).await?;
  if let Some(err) = &envelope.error {
    return Err(DomainError::from_bridge(envelope.status, err).into());
  }
  Ok(envelope)
}

/// Makes sure that the session has a bridge connection. It waits for a launch
/// that is in progress, or relaunches a disconnected or stale session.
pub async fn ensure_connected(state: &Arc<McpState>, md5: &str) -> Result<()> {
  let session = state.session(md5)?;
  if session.ws_connected {
    return Ok(());
  }
  if session.status.is_launching() {
    return wait_for_launch(state, md5).await;
  }
  if session.status.is_recoverable() {
    return recover(state, md5).await;
  }
  Err(DomainError::disconnected(md5).into())
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
  let (prepared, job_id) = {
    let guard = state.lifecycle_lock.lock().await;
    let current = state.session(md5)?;
    if current.ws_connected {
      return Ok(());
    }
    if current.status.is_launching() {
      drop(guard);
      return wait_for_launch(state, md5).await;
    }
    if !current.status.is_recoverable() {
      return Err(DomainError::disconnected(md5).into());
    }
    begin_launch(state, md5, job_kind::RECOVER_SESSION_BRIDGE).await?
  };
  launch_and_wait(state.clone(), prepared, job_id).await
}

/// Replaces a session with a new launch and its job. The caller must have the lifecycle lock.
async fn begin_launch(
  state: &McpState,
  md5: &str,
  kind: &'static str,
) -> Result<(PreparedProject, String)> {
  let paths = state.paths.clone();
  let binary_md5 = md5.to_string();
  let prepared = tokio::task::spawn_blocking(move || prepare_project(&paths, &binary_md5))
    .await
    .map_err(|err| DomainError::Internal {
      message: format!("project preparation task failed: {err}"),
    })??;
  // A disconnected bridge can leave its JVM alive. Stop that process before
  // you replace the session and its authentication token.
  state.detach_bridge(md5, "bridge restarting");
  state.stop_process(md5, Duration::ZERO).await;
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
  let result = match launch_process(&state, prepared).await {
    Ok(()) => wait_ready(&state, &md5, &job_id, state.config.launch_timeout())
      .await
      .map(drop),
    Err(err) => Err(err),
  };
  let outcome = result.map_err(|err| {
    // The anyhow chain keeps private details. The daemon log gets the chain.
    // The public typed error does not.
    crate::process::record_daemon_error(&format!("session {md5} launch failed: {err:#}"));
    DomainError::from_error(&err)
  });
  if let Err(error) = &outcome {
    state.fail_launch(&md5, &job_id, error.clone()).await;
  }
  outcome.map_err(Into::into)
}

/// Starts Ghidra and records the process. Does nothing if a newer launch
/// replaced this one or the shutdown started.
async fn launch_process(state: &Arc<McpState>, prepared: PreparedProject) -> Result<()> {
  let _guard = state.lifecycle_lock.lock().await;
  let md5 = prepared.md5.clone();
  if !state
    .session_with_token(&md5, &prepared.agent_token)
    .is_some_and(|session| session.status.is_launching())
  {
    return Err(DomainError::missing_target(md5, "binary launch was replaced or closed").into());
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

/// Makes the `analyzeHeadless` command line and environment, and starts the
/// process. Its output goes to the logs of the session. This function blocks.
fn spawn_ghidra(state: &McpState, prepared: &PreparedProject) -> Result<ManagedChild> {
  state.paths.ensure_layout()?;
  let analyze_headless = java_path(&crate::ghidra::analyze_headless(&state.config)?)?;
  let runtime_dir = &state.paths.runtime_dir;
  let jar = bridge::install_runtime(runtime_dir)?;

  let mut command = Command::new(analyze_headless);
  // On Unix, keep the visible project alias. On Windows, give usual paths to the
  // batch launcher and to Java, not canonical \\?\ paths.
  command
    .arg(java_path(&prepared.ghidra_launch_root)?)
    .arg(GHIDRA_PROJECT_NAME);
  let script = if prepared.existing_project {
    // With no -process or -import, headless runs the script before it opens a
    // program. The opener enables recovery and saves it before it starts Bridge.
    command.arg("-noanalysis");
    bridge::SAVED_PROJECT_SCRIPT_NAME
  } else {
    command
      .arg("-import")
      .arg(java_path(&prepared.input_path)?)
      .args(["-overwrite", "-noanalysis"]);
    bridge::BRIDGE_SCRIPT_NAME
  };
  command
    .arg("-max-cpu")
    .arg(state.config.analysis.max_cpu.to_string())
    .arg("-scriptPath")
    .arg(java_path(runtime_dir)?)
    .arg("-postScript")
    .arg(script)
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

/// Waits until the bridge is ready, and then completes the launch job. A
/// launch failure, an early process stop and a timeout are errors.
async fn wait_ready(
  state: &McpState,
  md5: &str,
  job_id: &str,
  timeout: Duration,
) -> Result<JobRecord> {
  let deadline = Instant::now() + timeout;
  loop {
    let guard = state.lifecycle_lock.lock().await;
    if !state.owns_launch(md5, job_id) {
      return Err(DomainError::missing_target(md5, "binary launch was replaced or closed").into());
    }
    let job = state.job(job_id)?;
    match job.status {
      JobStatus::Completed => return Ok(job),
      JobStatus::Failed => {
        return Err(
          DomainError::Internal {
            message: job.error.unwrap_or_else(|| "job failed".to_string()),
          }
          .into(),
        );
      }
      JobStatus::Running => {}
    }
    let session = state.session(md5)?;
    if session.status == SessionStatus::Ready {
      state.finish_job(job_id, Ok(json!({ "md5": md5, "status": session.status })));
      return state.job(job_id);
    }
    if session.status.is_terminal() {
      return Err(
        DomainError::Internal {
          message: session
            .last_error
            .unwrap_or_else(|| format!("session {md5} failed")),
        }
        .into(),
      );
    }
    if let Some(status) = state.poll_process_exit(md5)? {
      return Err(
        DomainError::Internal {
          message: format!(
            "analyzeHeadless exited before ghidra.ready for session {md5} with \
           {status}; inspect logs/{md5}/stdout.log and logs/{md5}/stderr.log"
          ),
        }
        .into(),
      );
    }
    if Instant::now() >= deadline {
      let message = format!("timed out waiting for ghidra.ready for session {md5}");
      state.stop_process(md5, Duration::ZERO).await;
      let _ = state.update_session(md5, |session| session.mark_error(&message));
      return Err(
        DomainError::AgentTimeout {
          md5: md5.to_string(),
          timeout_seconds: Some(timeout.as_secs()),
        }
        .into(),
      );
    }
    drop(guard);
    // Wake at least once each second to find a process that stopped.
    let wake = deadline.min(Instant::now() + Duration::from_secs(1));
    let _ = tokio::time::timeout_at(wake, state.notify.notified()).await;
  }
}

/// Closes a session through its bridge. If `force` is `true`, it kills the process.
pub async fn close(state: &McpState, md5: &str, force: bool) -> Result<()> {
  let _guard = state.lifecycle_lock.lock().await;
  let session = state.session(md5)?;
  if !force && session.ws_connected {
    // Let the bridge save the program. Then give its process time to stop.
    // A close never relaunches a bridge. For this reason, this code does not use `call`.
    let shutdown = bridge::request(
      state,
      md5,
      "session.shutdown",
      json!({}),
      Duration::from_secs(5),
    );
    let _ = shutdown.await;
    state
      .stop_process(md5, state.config.timeouts.bridge_disconnect_grace)
      .await;
  } else {
    state.stop_process(md5, Duration::ZERO).await;
  }
  state.detach_bridge(md5, "session closed");
  state.update_session(md5, |session| session.mark_closed(force))?;
  if let Some(job_id) = state.launch_job(md5) {
    state.fail_job_error(&job_id, DomainError::disconnected(md5));
  }
  state.set_launch_job(md5, None);
  Ok(())
}
