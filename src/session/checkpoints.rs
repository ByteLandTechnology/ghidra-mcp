// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Session checkpoints, clean project resets, and session deletion.
//!
//! Every operation in this module takes `lifecycle_lock` and `request_lock` in
//! [`McpState`] before it runs synchronous filesystem steps under exclusive
//! `binary.lock`.

use super::{begin_launch, launch_and_wait};
use crate::bridge;
use crate::checkpoint::{
    create_checkpoint, list_checkpoints, resolve_checkpoint, restore_checkpoint,
};
use crate::error::DomainError;
use crate::model::{job_kind, JobStatus, SessionRecord};
use crate::project::{
    delete_project, ensure_resettable_binary, is_attached_gpr_session, normalize_md5, reset_project,
};
use crate::state::McpState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OwnedMutexGuard;

/// Holds `lifecycle_lock` and, when a session entry exists, `request_lock`.
struct SessionMutationGuards {
    /// Serializes session lifecycle transitions.
    _lifecycle: OwnedMutexGuard<()>,
    /// Serializes bridge requests for the target session.
    _request: Option<OwnedMutexGuard<()>>,
}

/// Acquires `lifecycle_lock` and then `request_lock` for `md5` in fixed order.
async fn lock_session_mutation(state: &McpState, md5: &str) -> Result<SessionMutationGuards> {
    let lifecycle = state.lifecycle_lock(md5)?.lock_owned().await;
    let request = if let Some(lock) = state.find_request_lock(md5) {
        let timeout = state.config.timeouts.rpc;
        Some(
            tokio::time::timeout(timeout, lock.lock_owned())
                .await
                .map_err(|_| DomainError::session_lock_timeout(md5, timeout.as_secs()))?,
        )
    } else {
        None
    };
    Ok(SessionMutationGuards {
        _lifecycle: lifecycle,
        _request: request,
    })
}

/// Stops any active Ghidra process for `md5` without a save, detaches its bridge,
/// and fails active jobs for the session. The caller must hold `lifecycle_lock`.
async fn force_stop_without_save(state: &McpState, md5: &str, reason: &str) {
    state.stop_process(md5, Duration::ZERO).await;
    state.detach_bridge(md5, reason);
    let disconnected = DomainError::disconnected(md5);
    state.fail_session_jobs(md5, &disconnected);
    state.set_launch_job(md5, None);
}

/// Saves an active program and copies `project.gpr` and `project.rep/` into
/// `projects/<md5>/checkpoints/`.
pub async fn checkpoint_create(
    state: &Arc<McpState>,
    md5: &str,
    name: Option<String>,
) -> Result<(String, Value)> {
    let md5 = normalize_md5(md5)?;
    let _guards = lock_session_mutation(state, &md5).await?;
    if is_attached_gpr_session(&state.paths, &md5)? {
        return Err(DomainError::invalid_argument(
            "md5",
            "project checkpoints are not supported for attached .gpr projects",
        )
        .into());
    }
    let mut saved_live = false;
    if let Some(session) = state.find_session(&md5) {
        if session.attached {
            return Err(DomainError::invalid_argument(
                "md5",
                format!("session {md5} is attached to Ghidra GUI; save the project in Ghidra"),
            )
            .into());
        }
        if session.status.is_launching() {
            return Err(DomainError::invalid_argument(
                "md5",
                format!("session {md5} is starting; wait until it is ready"),
            )
            .into());
        }
        if session.ws_connected {
            let timeout = state.config.timeouts.rpc;
            let envelope = bridge::request_locked(
                state,
                &md5,
                "program.save",
                json!({}),
                timeout,
                timeout.as_secs(),
            )
            .await?;
            if let Some(err) = &envelope.error {
                return Err(DomainError::from_bridge(envelope.status, err).into());
            }
            saved_live = true;
        } else {
            state
                .stop_process(&md5, state.config.timeouts.bridge_disconnect_grace)
                .await;
        }
    }

    let paths = state.paths.clone();
    let max_per_binary = state.config.checkpoints.max_per_binary;
    let md5_clone = md5.clone();
    let created = tokio::task::spawn_blocking(move || {
        create_checkpoint(&paths, &md5_clone, name, max_per_binary)
    })
    .await
    .map_err(|err| DomainError::Internal {
        message: format!("checkpoint creation task failed: {err}"),
    })??;

    Ok((
        format!(
            "Created checkpoint {} for session {md5}",
            created.checkpoint.id
        ),
        json!({
            "md5": md5,
            "saved": saved_live,
            "checkpoint": created.checkpoint,
            "retainedCount": created.retained_count,
            "maxPerBinary": max_per_binary,
            "evictedIds": created.evicted_ids
        }),
    ))
}

/// Lists saved project checkpoints for `md5`, from newest to oldest.
pub async fn checkpoint_list(state: &McpState, md5: &str) -> Result<(String, Value)> {
    let md5 = normalize_md5(md5)?;
    let _guards = lock_session_mutation(state, &md5).await?;
    let paths = state.paths.clone();
    let md5_clone = md5.clone();
    let items = tokio::task::spawn_blocking(move || list_checkpoints(&paths, &md5_clone))
        .await
        .map_err(|err| DomainError::Internal {
            message: format!("checkpoint list task failed: {err}"),
        })??;
    let count = items.len();
    Ok((
        format!("Found {count} checkpoint(s) for session {md5}"),
        json!({
            "md5": md5,
            "items": items,
            "maxPerBinary": state.config.checkpoints.max_per_binary
        }),
    ))
}

/// Stops Ghidra without a save, replaces `projects/<md5>/ghidra/` atomically from
/// a saved checkpoint, and relaunches the session.
pub async fn checkpoint_restore(
    state: &Arc<McpState>,
    md5: &str,
    id: Option<String>,
    name: Option<String>,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    if state.is_shutting_down() {
        return Err(DomainError::ShuttingDown.into());
    }
    let md5 = normalize_md5(md5)?;
    let (restored, job_id) = {
        let _guards = lock_session_mutation(state, &md5).await?;
        if state.is_shutting_down() {
            return Err(DomainError::ShuttingDown.into());
        }
        let paths = state.paths.clone();
        let md5_check = md5.clone();
        let id_check = id.clone();
        let name_check = name.clone();
        let target = tokio::task::spawn_blocking(move || {
            resolve_checkpoint(
                &paths,
                &md5_check,
                id_check.as_deref(),
                name_check.as_deref(),
            )
        })
        .await
        .map_err(|err| DomainError::Internal {
            message: format!("checkpoint lookup task failed: {err}"),
        })??;

        force_stop_without_save(state, &md5, "restoring checkpoint").await;

        let paths = state.paths.clone();
        let md5_restore = md5.clone();
        let target_id = target.id.clone();
        let restored = tokio::task::spawn_blocking(move || {
            restore_checkpoint(&paths, &md5_restore, &target_id)
        })
        .await
        .map_err(|err| DomainError::Internal {
            message: format!("checkpoint restore task failed: {err}"),
        })??;

        let (prepared, job_id) =
            begin_launch(state, &md5, job_kind::RECOVER_SESSION_BRIDGE).await?;
        tokio::spawn(launch_and_wait(state.clone(), prepared, job_id.clone()));
        (restored, job_id)
    };

    let job = state.await_job(&job_id, wait).await?;
    if job.status == JobStatus::Failed {
        return Err(DomainError::Internal {
            message: job
                .error
                .unwrap_or_else(|| "Ghidra relaunch failed after checkpoint restore".to_string()),
        }
        .into());
    }
    let session = state.session(&md5)?;
    Ok((
        format!("Restored checkpoint {} for session {md5}", restored.id),
        json!({
            "md5": md5,
            "restored": true,
            "checkpoint": restored,
            "session": session.summary(),
            "jobId": job_id,
            "job": job
        }),
    ))
}

/// Stops Ghidra without a save, deletes `projects/<md5>/ghidra/` and checkpoints,
/// and keeps `binary` and `binary.json`. Relaunches a clean import when `open` is `true`.
pub async fn reset(
    state: &Arc<McpState>,
    md5: &str,
    open: bool,
    wait: Option<Duration>,
) -> Result<(String, Value)> {
    if open && state.is_shutting_down() {
        return Err(DomainError::ShuttingDown.into());
    }
    let md5 = normalize_md5(md5)?;
    let (file_name, launched_job) = {
        let _guards = lock_session_mutation(state, &md5).await?;
        if open && state.is_shutting_down() {
            return Err(DomainError::ShuttingDown.into());
        }
        let paths_check = state.paths.clone();
        let md5_check = md5.clone();
        tokio::task::spawn_blocking(move || ensure_resettable_binary(&paths_check, &md5_check))
            .await
            .map_err(|err| DomainError::Internal {
                message: format!("project reset validation task failed: {err}"),
            })??;

        force_stop_without_save(state, &md5, "session reset").await;

        let paths = state.paths.clone();
        let md5_reset = md5.clone();
        let file_name = tokio::task::spawn_blocking(move || reset_project(&paths, &md5_reset))
            .await
            .map_err(|err| DomainError::Internal {
                message: format!("project reset task failed: {err}"),
            })??;

        if open {
            let (prepared, job_id) = begin_launch(state, &md5, job_kind::ANALYZE_BINARY).await?;
            tokio::spawn(launch_and_wait(state.clone(), prepared, job_id.clone()));
            (file_name, Some(job_id))
        } else {
            let mut record = state.find_session(&md5).unwrap_or_else(|| {
                SessionRecord::launching(md5.clone(), file_name.clone(), String::new())
            });
            record.attached = false;
            record.mark_closed(true);
            state.put_session(&record)?;
            (file_name, None)
        }
    };

    if let Some(job_id) = launched_job {
        let job = state.await_job(&job_id, wait).await?;
        if job.status == JobStatus::Failed {
            return Err(DomainError::Internal {
                message: job
                    .error
                    .unwrap_or_else(|| "Ghidra launch failed after session reset".to_string()),
            }
            .into());
        }
        let session = state.session(&md5)?;
        return Ok((
            format!("Reset and reopened session {md5}"),
            json!({
                "md5": md5,
                "reset": true,
                "reopened": true,
                "fileName": file_name,
                "session": session.summary(),
                "jobId": job_id,
                "job": job
            }),
        ));
    }

    let session = state.session(&md5)?;
    Ok((
        format!("Reset session {md5}"),
        json!({
            "md5": md5,
            "reset": true,
            "reopened": false,
            "fileName": file_name,
            "session": session.summary()
        }),
    ))
}

/// Stops Ghidra without a save and deletes `projects/<md5>/`, `sessions/<md5>/`,
/// `logs/<md5>/`, and the in-memory session record.
pub async fn delete(state: &McpState, md5: &str) -> Result<(String, Value)> {
    let md5 = normalize_md5(md5)?;
    let _guards = lock_session_mutation(state, &md5).await?;
    let had_session = state.find_session(&md5).is_some();
    force_stop_without_save(state, &md5, "session deleted").await;
    state.remove_session(&md5);

    let paths = state.paths.clone();
    let md5_delete = md5.clone();
    let removed_files = tokio::task::spawn_blocking(move || delete_project(&paths, &md5_delete))
        .await
        .map_err(|err| DomainError::Internal {
            message: format!("project delete task failed: {err}"),
        })??;

    if !had_session && !removed_files {
        return Err(DomainError::missing_target(&md5, format!("unknown session: {md5}")).into());
    }
    Ok((
        format!("Deleted session {md5}"),
        json!({
            "md5": md5,
            "deleted": true
        }),
    ))
}
