// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Saved binaries and their Ghidra projects. The MD5 identifies each binary.
//!
//! Each binary has a persistent directory `projects/<md5>/`:
//!
//! ```text
//! projects/<md5>/
//! ├── binary        the saved binary, with a fixed name
//! ├── binary.json   {"fileName": …}, written last: it shows that the copy is complete
//! ├── binary.lock   serializes persistence for this MD5 and remains after lock release
//! └── ghidra/       the Ghidra project: project.gpr and project.rep/
//! ```
//!
//! The daemon saves a binary one time. After that, it opens the project again
//! by the MD5, without the original path.

use crate::error::DomainError;
use crate::model::SessionRecord;
use crate::paths::{atomic_write, persist_synced, sync_directory, McpPaths};
use anyhow::Result;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The file name of the saved binary in its project directory.
const BINARY_NAME: &str = "binary";
/// The file name of the metadata of the binary in its project directory.
const METADATA_NAME: &str = "binary.json";
/// The stable file on which readers and writers lock one binary.
const BINARY_LOCK_NAME: &str = "binary.lock";

/// The contents of `binary.json`.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BinaryMetadata {
    /// The original file name of the binary, for display.
    file_name: String,
}

/// Validates an MD5 and returns it in lowercase, its canonical form.
///
/// # Errors
///
/// Fails if `value` is not exactly 32 hexadecimal digits.
pub fn normalize_md5(value: &str) -> Result<String> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DomainError::invalid_argument(
            "md5",
            "md5 must contain exactly 32 hexadecimal characters",
        )
        .into());
    }
    Ok(value.to_ascii_lowercase())
}

/// Deserializes an optional MD5 argument with [`normalize_md5`]. JSON `null`
/// is the same as no value. Use it with `#[serde(default)]`.
///
/// # Errors
///
/// Fails if the value is not `null` or a string of 32 hexadecimal digits.
pub fn deserialize_optional_md5<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| normalize_md5(&value).map_err(D::Error::custom))
        .transpose()
}

/// Validates a display file name from a client.
///
/// # Errors
///
/// Fails for an empty name, for `.` and `..`, and for a name with a path
/// separator or a control character.
pub fn validate_file_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains(['/', '\\'])
        || value.chars().any(char::is_control)
    {
        return Err(DomainError::invalid_argument(
            "fileName",
            "fileName must be a nonempty filename without directory components",
        )
        .into());
    }
    Ok(())
}

/// Saves `source` as the binary `md5` with the display name `file_name`. If
/// the project already has the binary, the function does nothing.
///
/// The function copies the binary. It does not move it. Then the source can be
/// on a different file system. After the copy, the function examines the MD5.
///
/// It stages and synchronizes the binary before it publishes it.
/// Then it writes `binary.json` atomically as the completion marker.
/// A per-MD5 file lock prevents reads during publication.
/// Failed copies do not alter saved files.
///
/// # Errors
///
/// Fails for an incorrect MD5 or file name.
/// Also fails if the source changes during the copy or an I/O error occurs.
/// Rust removes temporary files on drop.
/// A failure after binary publication leaves it available for the next metadata write.
pub fn persist_binary(paths: &McpPaths, source: &Path, md5: &str, file_name: &str) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    validate_file_name(file_name)?;
    paths.ensure_layout()?;
    let project_dir = paths.project_dir(&md5);
    let _lock = lock_binary(&project_dir, true)?;
    // The daemon persists the MD5 directory and new home or project ancestors.
    // It does this before it commits files inside that directory.
    for directory in paths.projects_dir.ancestors() {
        if !directory.as_os_str().is_empty() {
            sync_directory(directory)?;
        }
    }
    let binary_path = project_dir.join(BINARY_NAME);
    let metadata_path = project_dir.join(METADATA_NAME);
    let metadata = read_metadata(paths, &md5)?;
    if metadata.is_some() && binary_path.is_file() {
        return Ok(());
    }
    // A binary with metadata keeps its first display name.
    let metadata = metadata.unwrap_or_else(|| BinaryMetadata {
        file_name: file_name.to_string(),
    });
    let mut staged = tempfile::Builder::new()
        .prefix(".binary-")
        .suffix(".tmp")
        .tempfile_in(&project_dir)
        .map_err(|err| DomainError::Internal {
            message: format!(
                "staging saved binary: {}",
                sanitize_error_path(&err, &project_dir)
            ),
        })?;
    copy_verified(source, staged.as_file_mut(), &md5)?;
    // Commit the binary and its directory entry before publication of the marker.
    // A publication failure must not remove shared persistent paths.
    persist_synced(staged, &binary_path)?;
    atomic_write(&metadata_path, &serde_json::to_vec(&metadata)?)
}

/// Masks sensitive server filesystem paths from error messages before exposure.
fn sanitize_error_path(err: &io::Error, path: &Path) -> String {
    let err_str = err.to_string();
    let path_str = path.to_string_lossy();
    let sanitized = if !path_str.is_empty() && err_str.contains(path_str.as_ref()) {
        err_str.replace(path_str.as_ref(), "<masked-path>")
    } else {
        err_str
    };
    let mut words = Vec::new();
    for word in sanitized.split_whitespace() {
        let trimmed =
            word.trim_matches(|c: char| c == '\'' || c == '"' || c == '(' || c == ')' || c == ':');
        if trimmed.starts_with('/')
            || (trimmed.len() >= 3
                && trimmed.as_bytes().get(1) == Some(&b':')
                && (trimmed.as_bytes().get(2) == Some(&b'\\')
                    || trimmed.as_bytes().get(2) == Some(&b'/')))
        {
            words.push(word.replace(trimmed, "<masked-path>"));
        } else {
            words.push(word.to_string());
        }
    }
    if words.is_empty() {
        sanitized
    } else {
        words.join(" ")
    }
}

/// Opens the stable per-MD5 lock. Writers have exclusive access.
/// Project preparation uses a shared lock.
fn lock_binary(project_dir: &Path, exclusive: bool) -> Result<File> {
    fs::create_dir_all(project_dir)?;
    // Keep the lock file in place. If you remove it, a later writer can lock a
    // different file while another writer still holds or waits on this one.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(project_dir.join(BINARY_LOCK_NAME))
        .map_err(|err| DomainError::Internal {
            message: format!(
                "opening binary persistence lock: {}",
                sanitize_error_path(&err, project_dir)
            ),
        })?;
    if exclusive {
        lock.lock().map_err(|err| DomainError::Internal {
            message: format!(
                "locking binary persistence: {}",
                sanitize_error_path(&err, project_dir)
            ),
        })?;
    } else {
        lock.lock_shared().map_err(|err| DomainError::Internal {
            message: format!(
                "waiting for binary persistence: {}",
                sanitize_error_path(&err, project_dir)
            ),
        })?;
    }
    Ok(lock)
}

/// Copies `source` into an owned temporary file and examines its MD5 in one pass.
fn copy_verified(source: &Path, output: &mut File, md5: &str) -> Result<()> {
    let mut input = File::open(source).map_err(|err| DomainError::Internal {
        message: format!(
            "opening binary source: {}",
            sanitize_error_path(&err, source)
        ),
    })?;
    let mut hasher = md5::Context::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let bytes_read = input
            .read(&mut buffer)
            .map_err(|err| DomainError::Internal {
                message: format!("reading binary source: {err}"),
            })?;
        if bytes_read == 0 {
            break;
        }
        output
            .write_all(&buffer[..bytes_read])
            .map_err(|err| DomainError::Internal {
                message: format!("saving binary: {err}"),
            })?;
        hasher.consume(&buffer[..bytes_read]);
    }
    let computed = format!("{:x}", hasher.compute());
    if computed != md5 {
        return Err(DomainError::invalid_argument(
            "md5",
            "binary content changed while it was being saved",
        )
        .into());
    }
    Ok(())
}

/// Reads `binary.json`. Returns `None` if the daemon did not complete the copy of the binary.
fn read_metadata(paths: &McpPaths, md5: &str) -> Result<Option<BinaryMetadata>> {
    let path = paths.project_dir(md5).join(METADATA_NAME);
    match fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<BinaryMetadata>(&bytes) {
            Ok(metadata) => {
                validate_file_name(&metadata.file_name)?;
                Ok(Some(metadata))
            }
            // Older versions can leave metadata that is not complete after a shutdown.
            Err(_) => Ok(None),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// All the data that the daemon needs to launch Ghidra for one saved binary.
#[derive(Debug, Clone)]
pub struct PreparedProject {
    /// The binary, and the session, of the launch.
    pub md5: String,
    /// The display name of the binary.
    pub file_name: String,
    /// The project root for `analyzeHeadless`. On Unix, it is the launch alias.
    pub ghidra_launch_root: PathBuf,
    /// The saved binary. Ghidra imports it if no project exists.
    pub input_path: PathBuf,
    /// A new 256-bit bridge credential for this launch.
    pub agent_token: String,
    /// `true` to open the saved program with recovery enabled, `false` to import the binary.
    pub existing_project: bool,
}

impl PreparedProject {
    /// Returns the session record for this launch.
    pub fn session_record(&self) -> SessionRecord {
        SessionRecord::launching(
            self.md5.clone(),
            self.file_name.clone(),
            self.agent_token.clone(),
        )
    }
}

/// Prepares the launch of Ghidra for a saved binary. It makes the project and
/// log directories. It also decides if Ghidra opens the project again or
/// imports the binary.
///
/// # Errors
///
/// Fails if the binary is not saved. Also fails if the project directory
/// contains an object that Ghidra cannot open as a project. The function does
/// not change that directory.
pub fn prepare_project(paths: &McpPaths, md5: &str) -> Result<PreparedProject> {
    paths.ensure_layout()?;
    let md5 = normalize_md5(md5)?;
    let project_dir = paths.project_dir(&md5);
    let _lock = lock_binary(&project_dir, false)?;
    let Some(metadata) = read_metadata(paths, &md5)? else {
        return Err(DomainError::missing_target(
            &md5,
            format!("binary {md5} is not available; upload the binary before opening it"),
        )
        .into());
    };
    let ghidra_root = paths.ghidra_project_root(&md5);
    fs::create_dir_all(&project_dir)?;
    for log in [paths.stdout_log(&md5), paths.stderr_log(&md5)] {
        fs::create_dir_all(log.parent().ok_or_else(|| DomainError::Internal {
            message: "log has no parent".to_string(),
        })?)?;
        OpenOptions::new().create(true).append(true).open(log)?;
    }

    // These files identify the project layout, not its database health. The
    // saved-program script permits Ghidra to open it with recovery enabled.
    let existing_project =
        ghidra_root.join("project.gpr").is_file() && ghidra_root.join("project.rep").is_dir();
    let has_binary = project_dir.join(BINARY_NAME).is_file();
    if !existing_project && !has_binary {
        return Err(DomainError::missing_target(
            md5.clone(),
            format!("binary {md5} is not available; upload the binary before opening it"),
        )
        .into());
    }
    if !existing_project && ghidra_root.exists() && fs::read_dir(&ghidra_root)?.next().is_some() {
        return Err(DomainError::Internal {
            message: format!(
                "existing Ghidra project cannot be reopened; preserving saved files for {md5}"
            ),
        }
        .into());
    }
    fs::create_dir_all(&ghidra_root)?;

    Ok(PreparedProject {
        ghidra_launch_root: paths.ghidra_launch_root(&md5),
        input_path: paths.binary_launch_path(&md5),
        file_name: metadata.file_name,
        agent_token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        existing_project,
        md5,
    })
}
