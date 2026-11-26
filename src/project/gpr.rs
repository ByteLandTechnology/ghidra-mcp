// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Local `.gpr` project inspection, deterministic 32-hex IDs, and read-only lock checks.

use super::{lock_binary, normalize_md5, LaunchMode, PreparedProject};
use crate::error::DomainError;
use crate::import::{is_gpr_path, normalize_program_name};
use crate::paths::{atomic_write, McpPaths};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// File name of attached `.gpr` metadata in `projects/<md5>/`.
const ATTACHED_METADATA_NAME: &str = "attached.json";
/// Marker line written by Ghidra when a `.lock` file uses a channel lock.
const CHANNEL_LOCK_MARKER: &str = "Supports File Channel Locking=Channel Lock";

/// Validated filesystem details of a local `.gpr` project.
#[derive(Debug, Clone)]
pub struct ResolvedGpr {
    /// Deterministic 32-hex session ID for this canonical `.gpr` path.
    pub md5: String,
    /// Canonical `.gpr` marker file path.
    pub gpr_path: PathBuf,
    /// Canonical parent directory of `<name>.gpr` and `<name>.rep`.
    pub parent_dir: PathBuf,
    /// Ghidra project name (`.gpr` stem).
    pub project_name: String,
    /// Display file name (`<name>.gpr`).
    pub file_name: String,
}

/// Persistent metadata for an attached `.gpr` session in `projects/<md5>/attached.json`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AttachedMetadata {
    /// Canonical `.gpr` file path.
    pub gpr_path: PathBuf,
    /// Ghidra project name.
    pub project_name: String,
    /// Display file name (`<name>.gpr`).
    pub file_name: String,
    /// Optional target program name or project path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_name: Option<String>,
}

/// Computes the deterministic 32-hex session ID for a canonical `.gpr` path.
pub fn gpr_session_id(canonical_gpr: &Path) -> String {
    let mut hasher = md5::Context::new();
    hasher.consume(b"ghidra-gpr:");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hasher.consume(canonical_gpr.as_os_str().as_bytes());
    }
    #[cfg(not(unix))]
    {
        hasher.consume(canonical_gpr.to_string_lossy().as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Resolves and validates a local `.gpr` file and its `.rep` directory.
///
/// # Errors
///
/// Fails when `path` is absent, is not `.gpr`, has a hidden name, or has no `.rep` folder.
pub fn resolve_gpr_path(path: &Path) -> Result<ResolvedGpr> {
    let canonical = path.canonicalize().map_err(|err| {
        DomainError::missing_target("path", format!("target path cannot be resolved: {err}"))
    })?;
    if !canonical.is_file() || !is_gpr_path(&canonical) {
        return Err(DomainError::invalid_argument(
            "path",
            "path must reference an existing .gpr file",
        )
        .into());
    }
    let file_name = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| DomainError::invalid_argument("path", ".gpr filename must be valid UTF-8"))?
        .to_string();
    let project_name = canonical
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty() && !stem.starts_with('.'))
        .ok_or_else(|| {
            DomainError::invalid_argument(
                "path",
                ".gpr project name must be nonempty and must not start with '.'",
            )
        })?
        .to_string();
    let parent_dir = canonical
        .parent()
        .ok_or_else(|| DomainError::invalid_argument("path", ".gpr file has no parent directory"))?
        .to_path_buf();
    let rep_dir = parent_dir.join(format!("{project_name}.rep"));
    if !rep_dir.is_dir() {
        return Err(DomainError::invalid_argument(
            "path",
            format!("Ghidra project directory '{project_name}.rep' is absent"),
        )
        .into());
    }
    Ok(ResolvedGpr {
        md5: gpr_session_id(&canonical),
        gpr_path: canonical,
        parent_dir,
        project_name,
        file_name,
    })
}

/// Checks for active Ghidra `.lock` files and does not create or change project files.
///
/// # Errors
///
/// Returns `InvalidArgument` when an active Ghidra lock is present.
pub fn check_gpr_not_locked(gpr: &ResolvedGpr) -> Result<()> {
    let lock_file = gpr.parent_dir.join(format!("{}.lock", gpr.project_name));
    let channel_lock_file = gpr.parent_dir.join(format!("{}.lock~", gpr.project_name));

    if has_active_os_lock(&channel_lock_file) {
        return Err(locked_project_error(&gpr.file_name));
    }
    if fs::symlink_metadata(&lock_file).is_ok() {
        if has_active_os_lock(&lock_file) {
            return Err(locked_project_error(&gpr.file_name));
        }
        let Some(contents) = read_text_readonly(&lock_file) else {
            return Err(locked_project_error(&gpr.file_name));
        };
        if !contents.contains(CHANNEL_LOCK_MARKER)
            || fs::symlink_metadata(&channel_lock_file).is_err()
        {
            return Err(locked_project_error(&gpr.file_name));
        }
    }
    Ok(())
}

/// Builds the client error for a locked `.gpr` project.
fn locked_project_error(file_name: &str) -> anyhow::Error {
    DomainError::invalid_argument(
        "path",
        format!(
            "Ghidra project '{file_name}' is locked by another Ghidra process; \
             close it in Ghidra GUI before opening a session"
        ),
    )
    .into()
}

/// Opens a file read-only and keeps `atime` unchanged on Linux when permitted.
fn open_readonly_noatime(path: &Path) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOATIME)
            .open(path)
        {
            return Ok(file);
        }
    }
    OpenOptions::new().read(true).open(path)
}

/// Reads UTF-8 text from `path` in read-only mode.
fn read_text_readonly(path: &Path) -> Option<String> {
    let mut file = open_readonly_noatime(path).ok()?;
    let mut text = String::new();
    file.read_to_string(&mut text).ok()?;
    Some(text)
}

/// Returns `true` if another process or descriptor holds an OS lock on `path`.
fn has_active_os_lock(path: &Path) -> bool {
    if fs::symlink_metadata(path).is_err() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let Ok(file) = open_readonly_noatime(path) else {
            return true;
        };
        let fd = file.as_raw_fd();
        let mut lock = libc::flock {
            l_type: i16::try_from(i64::from(libc::F_WRLCK)).unwrap_or(0),
            l_whence: i16::try_from(i64::from(libc::SEEK_SET)).unwrap_or(0),
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        // SAFETY: `fd` is a valid open descriptor and `lock` is an initialized `flock` struct.
        let status = unsafe { libc::fcntl(fd, libc::F_GETLK, &mut lock) };
        if status == 0 && i64::from(lock.l_type) != i64::from(libc::F_UNLCK) {
            return true;
        }
        // Check BSD `flock` locks without a wait or any disk change.
        // SAFETY: `fd` is a valid open descriptor; `LOCK_EX | LOCK_NB` and `LOCK_UN` are valid.
        let flock_rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if flock_rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return true;
            }
        } else {
            // SAFETY: Releases the immediate probe lock on the same descriptor.
            let _ = unsafe { libc::flock(fd, libc::LOCK_UN) };
        }
        false
    }
    #[cfg(windows)]
    {
        file_locked_windows(path)
    }
}

/// Probes whether `path` has an exclusive lock on Windows and makes no new files.
#[cfg(windows)]
fn file_locked_windows(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).open(path) else {
        return true;
    };
    match file.try_lock_shared() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(fs::TryLockError::WouldBlock) => true,
        Err(fs::TryLockError::Error(_)) => false,
    }
}

/// Saves attached `.gpr` metadata in `projects/<md5>/attached.json`.
///
/// # Errors
///
/// Fails when `program_name` is invalid or metadata cannot be written.
pub fn persist_attached_gpr(
    paths: &McpPaths,
    gpr: &ResolvedGpr,
    program_name: Option<&str>,
) -> Result<()> {
    let program_name = program_name.map(normalize_program_name).transpose()?;
    paths.ensure_layout()?;
    let project_dir = paths.project_dir(&gpr.md5);
    let _lock = lock_binary(&project_dir, true)?;
    let existing = read_attached_metadata(paths, &gpr.md5)?;
    let effective_program = program_name.or_else(|| existing.and_then(|item| item.program_name));
    let metadata = AttachedMetadata {
        gpr_path: gpr.gpr_path.clone(),
        project_name: gpr.project_name.clone(),
        file_name: gpr.file_name.clone(),
        program_name: effective_program,
    };
    atomic_write(
        &project_dir.join(ATTACHED_METADATA_NAME),
        &serde_json::to_vec(&metadata)?,
    )
}

/// Reads `attached.json` for `md5` if this session is an attached `.gpr` project.
pub(super) fn read_attached_metadata(
    paths: &McpPaths,
    md5: &str,
) -> Result<Option<AttachedMetadata>> {
    let path = paths.project_dir(md5).join(ATTACHED_METADATA_NAME);
    match fs::read(path) {
        Ok(bytes) => {
            let metadata: AttachedMetadata = serde_json::from_slice(&bytes)?;
            if let Some(program_name) = &metadata.program_name {
                normalize_program_name(program_name)?;
            }
            Ok(Some(metadata))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Returns `true` when `md5` refers to an attached `.gpr` session.
pub fn is_attached_gpr_session(paths: &McpPaths, md5: &str) -> Result<bool> {
    let md5 = normalize_md5(md5)?;
    Ok(read_attached_metadata(paths, &md5)?.is_some())
}

/// Returns the currently persisted `program_name` for an attached `.gpr` session.
pub fn attached_program_name(paths: &McpPaths, md5: &str) -> Result<Option<String>> {
    let md5 = normalize_md5(md5)?;
    Ok(read_attached_metadata(paths, &md5)?.and_then(|item| item.program_name))
}

/// Updates `program_name` for an attached `.gpr` session and checks `.lock` state.
///
/// # Errors
///
/// Fails when the `.gpr` file is absent, locked, or `program_name` is invalid.
pub fn update_attached_program_name(
    paths: &McpPaths,
    md5: &str,
    program_name: Option<&str>,
    daemon_owns_lock: bool,
) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    let program_name = program_name.map(normalize_program_name).transpose()?;
    let Some(mut metadata) = read_attached_metadata(paths, &md5)? else {
        return Err(DomainError::missing_target(
            &md5,
            format!("attached project {md5} is not available"),
        )
        .into());
    };
    let gpr = resolve_gpr_path(&metadata.gpr_path)?;
    if !daemon_owns_lock {
        check_gpr_not_locked(&gpr)?;
    }
    if let Some(program_name) = program_name {
        let project_dir = paths.project_dir(&md5);
        let _lock = lock_binary(&project_dir, true)?;
        metadata.program_name = Some(program_name);
        atomic_write(
            &project_dir.join(ATTACHED_METADATA_NAME),
            &serde_json::to_vec(&metadata)?,
        )?;
    }
    Ok(())
}

/// Prepares launch parameters for an attached `.gpr` session.
pub(super) fn prepare_attached_gpr(
    paths: &McpPaths,
    md5: &str,
    metadata: AttachedMetadata,
) -> Result<PreparedProject> {
    let gpr = resolve_gpr_path(&metadata.gpr_path)?;
    check_gpr_not_locked(&gpr)?;
    let ghidra_launch_root = paths.ensure_gpr_launch_alias(md5, &gpr.parent_dir)?;
    for log in [paths.stdout_log(md5), paths.stderr_log(md5)] {
        fs::create_dir_all(log.parent().ok_or_else(|| DomainError::Internal {
            message: "log has no parent".to_string(),
        })?)?;
        OpenOptions::new().create(true).append(true).open(log)?;
    }
    Ok(PreparedProject {
        md5: md5.to_string(),
        file_name: metadata.file_name,
        ghidra_launch_root,
        ghidra_project_name: gpr.project_name,
        agent_token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        launch_mode: LaunchMode::OpenSaved {
            attached_gpr: true,
            program_name: metadata.program_name,
            backup_dir: paths.recovery_backups_dir(md5),
        },
    })
}
