// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Persistent snapshots of saved Ghidra projects under `projects/<md5>/checkpoints/`.
//!
//! Each checkpoint directory contains `checkpoint.json` and a synchronized copy of
//! `project.gpr` and `project.rep/`. Creation stages into `.pending-<uuid>/`,
//! excludes temporary lock files, synchronizes files and directories, and renames
//! the directory atomically. When the checkpoint count exceeds `max_per_binary`,
//! the daemon removes the oldest snapshots.

use crate::error::DomainError;
use crate::paths::{atomic_write, sync_directory, McpPaths};
use crate::project::{lock_binary, normalize_md5, remove_entry, sanitize_error_path};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// File name of the JSON metadata file inside each checkpoint directory.
const CHECKPOINT_JSON_NAME: &str = "checkpoint.json";
/// Subdirectory inside each checkpoint that holds `project.gpr` and `project.rep/`.
const SNAPSHOT_GHIDRA_DIR: &str = "ghidra";
/// File name of the Ghidra project marker file.
const PROJECT_GPR_NAME: &str = "project.gpr";
/// Directory name of the Ghidra project repository.
const PROJECT_REP_NAME: &str = "project.rep";
/// Prefix for incomplete checkpoint directories.
const PENDING_PREFIX: &str = ".pending-";
/// Prefix for staged restore directories inside `projects/<md5>/`.
const RESTORE_STAGE_PREFIX: &str = ".restore-";
/// Prefix for replaced `ghidra/` directories during atomic swap.
const GHIDRA_OLD_PREFIX: &str = ".ghidra-old-";
/// Maximum length of an optional checkpoint name in Unicode scalar values.
const MAX_CHECKPOINT_NAME_CHARS: usize = 256;

/// Public metadata for one saved project checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointSummary {
    /// Stable identifier of the checkpoint directory.
    pub id: String,
    /// Lowercase MD5 of the binary session.
    pub md5: String,
    /// Optional human-readable name from the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Creation timestamp in RFC 3339 UTC format.
    pub created_at: String,
    /// Creation timestamp in milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    /// Total byte size of `project.gpr` and `project.rep/`.
    pub size_bytes: u64,
}

/// Outcome of `create_checkpoint`, with retention counts.
#[derive(Debug, Clone)]
pub struct CreatedCheckpoint {
    /// Metadata of the new checkpoint.
    pub checkpoint: CheckpointSummary,
    /// Number of checkpoints kept for this binary after eviction.
    pub retained_count: usize,
    /// Identifiers of oldest checkpoints evicted by `max_per_binary`.
    pub evicted_ids: Vec<String>,
}

/// Validates and normalizes an optional checkpoint name.
fn normalize_name(name: Option<String>) -> Result<Option<String>> {
    let Some(raw) = name else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_CHECKPOINT_NAME_CHARS {
        return Err(DomainError::invalid_argument(
            "name",
            format!("checkpoint name exceeds {MAX_CHECKPOINT_NAME_CHARS} characters"),
        )
        .into());
    }
    if trimmed.chars().any(char::is_control) {
        return Err(DomainError::invalid_argument(
            "name",
            "checkpoint name must not contain control characters",
        )
        .into());
    }
    Ok(Some(trimmed.to_string()))
}

/// Validates a checkpoint identifier before it becomes a directory segment.
pub fn validate_checkpoint_id(id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && !id.starts_with('.')
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if !valid {
        return Err(DomainError::invalid_argument(
            "id",
            "checkpoint id must contain only ASCII letters, digits, '-' or '_'",
        )
        .into());
    }
    Ok(())
}

/// Returns `true` for Ghidra lock files that snapshots must exclude.
fn is_transient_lock_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(".lock")
        || name.eq_ignore_ascii_case(".lock~")
        || Path::new(name).extension().is_some_and(|ext| {
            ext.eq_ignore_ascii_case("lock") || ext.eq_ignore_ascii_case("lock~")
        })
}

/// Formats Unix epoch milliseconds into RFC 3339 UTC and compact ID timestamps.
fn format_utc_millis(epoch_ms: u64) -> (String, String) {
    let total_secs = epoch_ms / 1_000;
    let millis = epoch_ms % 1_000;
    let days = i64::try_from(total_secs / 86_400).unwrap_or(0);
    let day_secs = total_secs % 86_400;
    let hour = day_secs / 3_600;
    let minute = (day_secs % 3_600) / 60;
    let second = day_secs % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097).cast_unsigned();
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = i64::try_from(yoe).unwrap_or(0) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"),
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}{millis:03}Z"),
    )
}

/// Copies `project.gpr` and `project.rep/` from `source_ghidra` into `dest_ghidra`.
/// Synchronizes all files and directories and returns the copied byte count.
fn copy_ghidra_snapshot(source_ghidra: &Path, dest_ghidra: &Path) -> Result<u64> {
    let gpr_source = source_ghidra.join(PROJECT_GPR_NAME);
    let rep_source = source_ghidra.join(PROJECT_REP_NAME);
    if !gpr_source.is_file() || !rep_source.is_dir() {
        return Err(DomainError::missing_target(
            PROJECT_GPR_NAME,
            "saved Ghidra project is not available; open and save the binary first",
        )
        .into());
    }
    fs::create_dir_all(dest_ghidra).map_err(|err| DomainError::Internal {
        message: format!(
            "creating checkpoint directory: {}",
            sanitize_error_path(&err, dest_ghidra)
        ),
    })?;
    let mut total_bytes = copy_file_synced(&gpr_source, &dest_ghidra.join(PROJECT_GPR_NAME))?;
    total_bytes = total_bytes.saturating_add(copy_dir_synced(
        &rep_source,
        &dest_ghidra.join(PROJECT_REP_NAME),
    )?);
    sync_directory(dest_ghidra)?;
    Ok(total_bytes)
}

/// Copies one regular file, refuses symbolic links, and synchronizes the destination file.
fn copy_file_synced(source: &Path, destination: &Path) -> Result<u64> {
    let meta = fs::symlink_metadata(source).map_err(|err| DomainError::Internal {
        message: format!(
            "reading project file: {}",
            sanitize_error_path(&err, source)
        ),
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(DomainError::Internal {
            message: "refusing non-regular file in Ghidra project snapshot".to_string(),
        }
        .into());
    }
    let mut input = File::open(source).map_err(|err| DomainError::Internal {
        message: format!(
            "opening project file: {}",
            sanitize_error_path(&err, source)
        ),
    })?;
    let mut output = File::create(destination).map_err(|err| DomainError::Internal {
        message: format!(
            "creating snapshot file: {}",
            sanitize_error_path(&err, destination)
        ),
    })?;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut copied = 0u64;
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|err| DomainError::Internal {
                message: format!(
                    "reading project file: {}",
                    sanitize_error_path(&err, source)
                ),
            })?;
        if count == 0 {
            break;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|err| DomainError::Internal {
                message: format!(
                    "writing snapshot file: {}",
                    sanitize_error_path(&err, destination)
                ),
            })?;
        copied = copied.saturating_add(count as u64);
    }
    output.sync_all().map_err(|err| DomainError::Internal {
        message: format!(
            "synchronizing snapshot file: {}",
            sanitize_error_path(&err, destination)
        ),
    })?;
    Ok(copied)
}

/// Copies a directory tree, skips `.lock` and `.lock~` files, refuses symbolic links,
/// and synchronizes each directory.
fn copy_dir_synced(source: &Path, destination: &Path) -> Result<u64> {
    let meta = fs::symlink_metadata(source).map_err(|err| DomainError::Internal {
        message: format!(
            "reading project directory: {}",
            sanitize_error_path(&err, source)
        ),
    })?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(DomainError::Internal {
            message: "refusing non-directory entry in Ghidra project repository".to_string(),
        }
        .into());
    }
    fs::create_dir_all(destination).map_err(|err| DomainError::Internal {
        message: format!(
            "creating snapshot directory: {}",
            sanitize_error_path(&err, destination)
        ),
    })?;
    let mut total_bytes = 0u64;
    for entry in fs::read_dir(source).map_err(|err| DomainError::Internal {
        message: format!(
            "listing project directory: {}",
            sanitize_error_path(&err, source)
        ),
    })? {
        let entry = entry.map_err(|err| DomainError::Internal {
            message: format!(
                "reading project directory entry: {}",
                sanitize_error_path(&err, source)
            ),
        })?;
        let file_name = entry.file_name();
        if let Some(name_str) = file_name.to_str() {
            if is_transient_lock_name(name_str) {
                continue;
            }
        }
        let entry_path = entry.path();
        let file_type = fs::symlink_metadata(&entry_path)
            .map_err(|err| DomainError::Internal {
                message: format!(
                    "inspecting project entry: {}",
                    sanitize_error_path(&err, &entry_path)
                ),
            })?
            .file_type();
        if file_type.is_symlink() {
            return Err(DomainError::Internal {
                message: "refusing symbolic link in Ghidra project repository".to_string(),
            }
            .into());
        }
        let target_path = destination.join(&file_name);
        if file_type.is_dir() {
            total_bytes = total_bytes.saturating_add(copy_dir_synced(&entry_path, &target_path)?);
        } else if file_type.is_file() {
            total_bytes = total_bytes.saturating_add(copy_file_synced(&entry_path, &target_path)?);
        }
    }
    sync_directory(destination)?;
    Ok(total_bytes)
}

/// Removes incomplete directories whose names start with `prefix` inside `parent`.
fn remove_prefixed_entries(parent: &Path, prefix: &str) -> Result<()> {
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(DomainError::Internal {
                message: format!(
                    "listing project directory: {}",
                    sanitize_error_path(&err, parent)
                ),
            }
            .into());
        }
    };
    for entry in entries {
        let entry = entry.map_err(|err| DomainError::Internal {
            message: format!(
                "reading project directory entry: {}",
                sanitize_error_path(&err, parent)
            ),
        })?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(prefix))
        {
            remove_entry(&entry.path())?;
        }
    }
    Ok(())
}

/// Reads all complete checkpoints in `checkpoints_dir`, sorted from newest to oldest.
fn read_checkpoints_unlocked(checkpoints_dir: &Path, md5: &str) -> Result<Vec<CheckpointSummary>> {
    let entries = match fs::read_dir(checkpoints_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(DomainError::Internal {
                message: format!(
                    "listing checkpoints: {}",
                    sanitize_error_path(&err, checkpoints_dir)
                ),
            }
            .into());
        }
    };
    let mut items = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| DomainError::Internal {
            message: format!(
                "reading checkpoint entry: {}",
                sanitize_error_path(&err, checkpoints_dir)
            ),
        })?;
        let Some(dir_name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if dir_name.starts_with('.') {
            continue;
        }
        let dir_path = entry.path();
        if !dir_path.is_dir() {
            continue;
        }
        if let Some(summary) = read_single_checkpoint(&dir_path, &dir_name, md5) {
            items.push(summary);
        }
    }
    items.sort_by_key(|item| (Reverse(item.created_at_ms), Reverse(item.id.clone())));
    Ok(items)
}

/// Reads and validates one checkpoint directory. Returns `None` if incomplete.
fn read_single_checkpoint(dir_path: &Path, dir_name: &str, md5: &str) -> Option<CheckpointSummary> {
    let ghidra_dir = dir_path.join(SNAPSHOT_GHIDRA_DIR);
    if !ghidra_dir.join(PROJECT_GPR_NAME).is_file() || !ghidra_dir.join(PROJECT_REP_NAME).is_dir() {
        return None;
    }
    let bytes = fs::read(dir_path.join(CHECKPOINT_JSON_NAME)).ok()?;
    let mut summary: CheckpointSummary = serde_json::from_slice(&bytes).ok()?;
    if summary.id != dir_name || summary.md5 != md5 {
        summary.id = dir_name.to_string();
        summary.md5 = md5.to_string();
    }
    Some(summary)
}

/// Creates a synchronized snapshot of `projects/<md5>/ghidra/` under exclusive `binary.lock`
/// and evicts the oldest snapshots above `max_per_binary`.
pub fn create_checkpoint(
    paths: &McpPaths,
    md5: &str,
    name: Option<String>,
    max_per_binary: usize,
) -> Result<CreatedCheckpoint> {
    paths.ensure_layout()?;
    let md5 = normalize_md5(md5)?;
    let normalized_name = normalize_name(name)?;
    let max_retained = max_per_binary.max(1);
    let project_dir = paths.project_dir(&md5);
    if !project_dir.is_dir() {
        return Err(DomainError::missing_target(
            &md5,
            format!("project {md5} does not exist; open the binary first"),
        )
        .into());
    }
    let _lock = lock_binary(&project_dir, true)?;
    let source_ghidra = paths.ghidra_project_root(&md5);
    if !source_ghidra.join(PROJECT_GPR_NAME).is_file()
        || !source_ghidra.join(PROJECT_REP_NAME).is_dir()
    {
        return Err(DomainError::missing_target(
            &md5,
            format!("saved Ghidra project for {md5} is not available yet"),
        )
        .into());
    }

    let checkpoints_dir = paths.checkpoints_dir(&md5);
    fs::create_dir_all(&checkpoints_dir).map_err(|err| DomainError::Internal {
        message: format!(
            "creating checkpoints directory: {}",
            sanitize_error_path(&err, &checkpoints_dir)
        ),
    })?;
    remove_prefixed_entries(&checkpoints_dir, PENDING_PREFIX)?;

    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        });
    let (created_at, compact_ts) = format_utc_millis(created_at_ms);
    let suffix = &Uuid::new_v4().simple().to_string()[..8];
    let id = format!("{compact_ts}-{suffix}");
    let stage_dir = checkpoints_dir.join(format!("{PENDING_PREFIX}{}", Uuid::new_v4().simple()));
    let final_dir = checkpoints_dir.join(&id);

    let copy_result = (|| -> Result<CheckpointSummary> {
        let size_bytes =
            copy_ghidra_snapshot(&source_ghidra, &stage_dir.join(SNAPSHOT_GHIDRA_DIR))?;
        let summary = CheckpointSummary {
            id: id.clone(),
            md5: md5.clone(),
            name: normalized_name,
            created_at,
            created_at_ms,
            size_bytes,
        };
        atomic_write(
            &stage_dir.join(CHECKPOINT_JSON_NAME),
            &serde_json::to_vec_pretty(&summary)?,
        )?;
        sync_directory(&stage_dir)?;
        fs::rename(&stage_dir, &final_dir).map_err(|err| DomainError::Internal {
            message: format!(
                "publishing checkpoint snapshot: {}",
                sanitize_error_path(&err, &final_dir)
            ),
        })?;
        sync_directory(&checkpoints_dir)?;
        Ok(summary)
    })();

    let checkpoint = match copy_result {
        Ok(summary) => summary,
        Err(err) => {
            let _ = remove_entry(&stage_dir);
            return Err(err);
        }
    };

    let mut all = read_checkpoints_unlocked(&checkpoints_dir, &md5)?;
    let mut evicted_ids = Vec::new();
    while all.len() > max_retained {
        if let Some(oldest) = all.pop() {
            remove_entry(&checkpoints_dir.join(&oldest.id))?;
            evicted_ids.push(oldest.id);
        }
    }
    if !evicted_ids.is_empty() {
        sync_directory(&checkpoints_dir)?;
    }
    Ok(CreatedCheckpoint {
        checkpoint,
        retained_count: all.len(),
        evicted_ids,
    })
}

/// Lists all saved checkpoints for `md5` from newest to oldest under exclusive `binary.lock`.
pub fn list_checkpoints(paths: &McpPaths, md5: &str) -> Result<Vec<CheckpointSummary>> {
    let md5 = normalize_md5(md5)?;
    let project_dir = paths.project_dir(&md5);
    if !project_dir.is_dir() {
        return Err(
            DomainError::missing_target(&md5, format!("project {md5} does not exist")).into(),
        );
    }
    let _lock = lock_binary(&project_dir, true)?;
    read_checkpoints_unlocked(&paths.checkpoints_dir(&md5), &md5)
}

/// Finds a target checkpoint by `id`, by `name`, or selects the newest checkpoint
/// before the daemon stops a live Ghidra process.
pub fn resolve_checkpoint(
    paths: &McpPaths,
    md5: &str,
    id: Option<&str>,
    name: Option<&str>,
) -> Result<CheckpointSummary> {
    if id.is_some() && name.is_some() {
        return Err(DomainError::invalid_argument("id", "provide id or name, not both").into());
    }
    if let Some(target_id) = id {
        validate_checkpoint_id(target_id)?;
    }
    let normalized_name = match name {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(DomainError::invalid_argument(
                    "name",
                    "checkpoint name must not be empty",
                )
                .into());
            }
            Some(trimmed)
        }
        None => None,
    };
    let items = list_checkpoints(paths, md5)?;
    if let Some(target_id) = id {
        return items
            .into_iter()
            .find(|item| item.id == target_id)
            .ok_or_else(|| {
                DomainError::missing_target(
                    target_id,
                    format!("checkpoint {target_id} does not exist for session {md5}"),
                )
                .into()
            });
    }
    if let Some(target_name) = normalized_name {
        return items
            .into_iter()
            .find(|item| item.name.as_deref() == Some(target_name))
            .ok_or_else(|| {
                DomainError::missing_target(
                    target_name,
                    format!("checkpoint named '{target_name}' does not exist for session {md5}"),
                )
                .into()
            });
    }
    items.into_iter().next().ok_or_else(|| {
        DomainError::missing_target(md5, format!("no checkpoints exist for session {md5}")).into()
    })
}

/// Restores an interrupted `.ghidra-old-*` backup if `ghidra/` is absent.
fn recover_interrupted_swap(project_dir: &Path, ghidra_root: &Path) -> Result<()> {
    if ghidra_root.exists() {
        return Ok(());
    }
    let entries = match fs::read_dir(project_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(DomainError::Internal {
                message: format!(
                    "listing project directory: {}",
                    sanitize_error_path(&err, project_dir)
                ),
            }
            .into());
        }
    };
    for entry in entries {
        let entry = entry.map_err(|err| DomainError::Internal {
            message: format!(
                "reading project directory entry: {}",
                sanitize_error_path(&err, project_dir)
            ),
        })?;
        let candidate = entry.path();
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(GHIDRA_OLD_PREFIX))
            && candidate.is_dir()
        {
            fs::rename(&candidate, ghidra_root).map_err(|err| DomainError::Internal {
                message: format!(
                    "recovering interrupted Ghidra project backup: {}",
                    sanitize_error_path(&err, ghidra_root)
                ),
            })?;
            sync_directory(project_dir)?;
            break;
        }
    }
    Ok(())
}

/// Atomically replaces `projects/<md5>/ghidra/` with a synchronized copy of checkpoint `id`
/// under exclusive `binary.lock`.
pub fn restore_checkpoint(paths: &McpPaths, md5: &str, id: &str) -> Result<CheckpointSummary> {
    paths.ensure_layout()?;
    let md5 = normalize_md5(md5)?;
    validate_checkpoint_id(id)?;
    let project_dir = paths.project_dir(&md5);
    if !project_dir.is_dir() {
        return Err(
            DomainError::missing_target(&md5, format!("project {md5} does not exist")).into(),
        );
    }
    let _lock = lock_binary(&project_dir, true)?;
    let ghidra_root = paths.ghidra_project_root(&md5);
    recover_interrupted_swap(&project_dir, &ghidra_root)?;
    let snapshot_dir = paths.checkpoints_dir(&md5).join(id);
    let summary = read_single_checkpoint(&snapshot_dir, id, &md5).ok_or_else(|| {
        DomainError::missing_target(
            id,
            format!("checkpoint {id} does not exist for session {md5}"),
        )
    })?;

    remove_prefixed_entries(&project_dir, RESTORE_STAGE_PREFIX)?;
    remove_prefixed_entries(&project_dir, GHIDRA_OLD_PREFIX)?;

    let stage_dir = project_dir.join(format!("{RESTORE_STAGE_PREFIX}{}", Uuid::new_v4().simple()));
    if let Err(err) = copy_ghidra_snapshot(&snapshot_dir.join(SNAPSHOT_GHIDRA_DIR), &stage_dir) {
        let _ = remove_entry(&stage_dir);
        return Err(err);
    }

    let backup_dir = project_dir.join(format!("{GHIDRA_OLD_PREFIX}{}", Uuid::new_v4().simple()));
    let had_existing = ghidra_root.exists();
    if had_existing {
        fs::rename(&ghidra_root, &backup_dir).map_err(|err| {
            let _ = remove_entry(&stage_dir);
            DomainError::Internal {
                message: format!(
                    "moving current Ghidra project aside: {}",
                    sanitize_error_path(&err, &ghidra_root)
                ),
            }
        })?;
    }

    if let Err(err) = fs::rename(&stage_dir, &ghidra_root) {
        let _ = remove_entry(&stage_dir);
        if had_existing {
            let _ = fs::rename(&backup_dir, &ghidra_root);
        }
        return Err(DomainError::Internal {
            message: format!(
                "activating restored Ghidra project: {}",
                sanitize_error_path(&err, &ghidra_root)
            ),
        }
        .into());
    }
    sync_directory(&project_dir)?;
    if had_existing {
        let _ = remove_entry(&backup_dir);
        sync_directory(&project_dir)?;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests;
