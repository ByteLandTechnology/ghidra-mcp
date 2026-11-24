// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Saved binaries, attached `.gpr` projects, and their launch preparation.
//!
//! Each binary has a persistent directory `projects/<md5>/`:
//!
//! ```text
//! projects/<md5>/
//! ├── binary(.ext)  the saved binary, with .bin, .hex, .ihex, or .srec extensions
//! ├── binary.json   {"fileName": …}, written last: it shows that the copy is complete
//! ├── binary.lock   serializes persistence for this MD5 and remains after lock release
//! └── ghidra/       the Ghidra project: project.gpr and project.rep/
//! ```
//!
//! Attached `.gpr` projects store `attached.json` in `projects/<md5>/` and keep
//! `<name>.gpr` and `<name>.rep/` in place through a non-hidden Unix alias.

mod gpr;

pub use gpr::{
    attached_program_name, check_gpr_not_locked, is_attached_gpr_session, persist_attached_gpr,
    resolve_gpr_path, update_attached_program_name,
};

use crate::error::DomainError;
use crate::import::{saved_binary_name, ImportOptions};
use crate::model::SessionRecord;
use crate::paths::{atomic_write, persist_synced, sync_directory, McpPaths};
use anyhow::Result;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Default file name of the saved binary in its project directory.
const BINARY_NAME: &str = "binary";
/// The file name of the metadata of the binary in its project directory.
const METADATA_NAME: &str = "binary.json";
/// The stable file on which readers and writers lock one binary.
const BINARY_LOCK_NAME: &str = "binary.lock";
/// Default Ghidra project name for internal binary projects.
const INTERNAL_PROJECT_NAME: &str = "project";

/// The contents of `binary.json`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BinaryMetadata {
    /// The original file name of the binary, for display.
    file_name: String,
    /// Saved file name inside `projects/<md5>/` (`binary` or `binary.<ext>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    saved_name: Option<String>,
    /// Optional Ghidra language and loader flags for `-import`.
    #[serde(default, skip_serializing_if = "ImportOptions::is_empty")]
    import_options: ImportOptions,
    /// True when the next launch must discard `ghidra/` and run `-import` again.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    reimport_pending: bool,
}

impl BinaryMetadata {
    /// Returns the persisted binary file name in `projects/<md5>/`.
    fn effective_saved_name(&self) -> String {
        self.saved_name
            .clone()
            .unwrap_or_else(|| saved_binary_name(&self.file_name))
    }
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

/// Saves `source` as the binary `md5`. It keeps `.bin`, `.hex`, `.ihex`, and `.srec`
/// extensions on the import path and stores `import_options` and `reimport`.
///
/// # Errors
///
/// Fails for an incorrect MD5, file name, or incomplete import options, or on I/O failure.
pub fn persist_binary_with_options(
    paths: &McpPaths,
    source: &Path,
    md5: &str,
    file_name: &str,
    import_options: &ImportOptions,
    reimport: bool,
) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    validate_file_name(file_name)?;
    paths.ensure_layout()?;
    let project_dir = paths.project_dir(&md5);
    let _lock = lock_binary(&project_dir, true)?;
    for directory in paths.projects_dir.ancestors() {
        if !directory.as_os_str().is_empty() {
            sync_directory(directory)?;
        }
    }
    let metadata_path = project_dir.join(METADATA_NAME);
    let requested_saved_name = saved_binary_name(file_name);

    if let Some(mut existing) = read_metadata(paths, &md5)? {
        let current_name = existing.effective_saved_name();
        let current_path = project_dir.join(&current_name);
        let fallback_path = project_dir.join(BINARY_NAME);
        if current_path.is_file() || fallback_path.is_file() {
            if requested_saved_name != BINARY_NAME
                && !project_dir.join(&requested_saved_name).is_file()
            {
                let src = if current_path.is_file() {
                    &current_path
                } else {
                    &fallback_path
                };
                fs::copy(src, project_dir.join(&requested_saved_name))?;
                existing.saved_name = Some(requested_saved_name);
                existing.file_name = file_name.to_string();
            } else if existing.saved_name.is_none() && current_path.is_file() {
                existing.saved_name = Some(current_name);
            }
            let mut next_options = existing.import_options.clone();
            next_options.merge_from(import_options);
            next_options.validate_complete()?;
            if !reimport
                && !existing.reimport_pending
                && next_options != existing.import_options
                && has_saved_internal_project(paths, &md5)
            {
                return Err(DomainError::invalid_argument(
                    "reimport",
                    "saved project already exists with different import options; \
                     set reimport=true to replace it",
                )
                .into());
            }
            existing.import_options = next_options;
            if reimport {
                existing.reimport_pending = true;
            }
            return atomic_write(&metadata_path, &serde_json::to_vec(&existing)?);
        }
    }

    let mut merged = ImportOptions::default();
    merged.merge_from(import_options);
    merged.validate_complete()?;
    let target_path = project_dir.join(&requested_saved_name);
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
    persist_synced(staged, &target_path)?;
    if requested_saved_name != BINARY_NAME {
        let plain = project_dir.join(BINARY_NAME);
        if !plain.exists() {
            let _ = fs::hard_link(&target_path, &plain);
        }
    }
    let metadata = BinaryMetadata {
        file_name: file_name.to_string(),
        saved_name: Some(requested_saved_name),
        import_options: merged,
        reimport_pending: reimport,
    };
    atomic_write(&metadata_path, &serde_json::to_vec(&metadata)?)
}

/// Updates saved binary import flags or sets `reimport` for an `md5` session open.
///
/// # Errors
///
/// Fails when the binary is absent or the merged options have `compilerSpec` without `processor`.
pub fn update_binary_import_options(
    paths: &McpPaths,
    md5: &str,
    import_options: &ImportOptions,
    reimport: bool,
) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    let project_dir = paths.project_dir(&md5);
    let _lock = lock_binary(&project_dir, true)?;
    let Some(mut metadata) = read_metadata(paths, &md5)? else {
        import_options.validate_complete()?;
        return Err(DomainError::missing_target(
            &md5,
            format!("binary {md5} is not available; upload the binary before opening it"),
        )
        .into());
    };
    if import_options.is_empty() && !reimport {
        return Ok(());
    }
    let mut next_options = metadata.import_options.clone();
    next_options.merge_from(import_options);
    next_options.validate_complete()?;
    if !reimport
        && !metadata.reimport_pending
        && next_options != metadata.import_options
        && has_saved_internal_project(paths, &md5)
    {
        return Err(DomainError::invalid_argument(
            "reimport",
            "saved project already exists with different import options; \
             set reimport=true to replace it",
        )
        .into());
    }
    metadata.import_options = next_options;
    if reimport {
        metadata.reimport_pending = true;
    }
    atomic_write(
        &project_dir.join(METADATA_NAME),
        &serde_json::to_vec(&metadata)?,
    )
}

/// Returns `true` when `projects/<md5>/ghidra` holds a saved internal `.gpr` project.
fn has_saved_internal_project(paths: &McpPaths, md5: &str) -> bool {
    let ghidra_root = paths.ghidra_project_root(md5);
    ghidra_root.join("project.gpr").is_file() && ghidra_root.join("project.rep").is_dir()
}

/// Returns `true` when `binary.json` sets `reimport_pending`.
pub fn is_reimport_pending(paths: &McpPaths, md5: &str) -> Result<bool> {
    let md5 = normalize_md5(md5)?;
    Ok(read_metadata(paths, &md5)?.is_some_and(|metadata| metadata.reimport_pending))
}

/// Removes `projects/<md5>/ghidra` and clears `reimport_pending` after the JVM stops.
///
/// # Errors
///
/// Fails if directory removal or metadata update fails.
pub fn reset_binary_ghidra_project(paths: &McpPaths, md5: &str) -> Result<()> {
    let md5 = normalize_md5(md5)?;
    let project_dir = paths.project_dir(&md5);
    let _lock = lock_binary(&project_dir, true)?;
    let ghidra_root = paths.ghidra_project_root(&md5);
    if ghidra_root.exists() {
        fs::remove_dir_all(&ghidra_root)?;
    }
    if let Some(mut metadata) = read_metadata(paths, &md5)? {
        if metadata.reimport_pending {
            metadata.reimport_pending = false;
            atomic_write(
                &project_dir.join(METADATA_NAME),
                &serde_json::to_vec(&metadata)?,
            )?;
        }
    }
    Ok(())
}

/// Masks sensitive server filesystem paths from error messages before exposure.
pub(crate) fn sanitize_error_path(err: &io::Error, path: &Path) -> String {
    let err_str = err.to_string();
    let path_str = path.to_string_lossy();
    let sanitized = if !path_str.is_empty() && err_str.contains(path_str.as_ref()) {
        err_str.replace(path_str.as_ref(), "<masked-path>")
    } else {
        err_str
    };
    sanitize_text_paths(&sanitized)
}

/// Masks absolute Unix and Windows filesystem paths in diagnostic text.
pub(crate) fn sanitize_text_paths(raw: &str) -> String {
    let mut words = Vec::new();
    for word in raw.split_whitespace() {
        let trimmed =
            word.trim_matches(|c: char| matches!(c, '\'' | '"' | '(' | ')' | ':' | ',' | ';'));
        let is_windows_abs = trimmed.len() >= 3
            && trimmed.as_bytes().get(1) == Some(&b':')
            && matches!(trimmed.as_bytes().get(2), Some(&b'\\' | &b'/'));
        if trimmed.starts_with('/') || is_windows_abs {
            words.push(word.replace(trimmed, "<masked-path>"));
        } else {
            words.push(word.to_string());
        }
    }
    if words.is_empty() {
        raw.to_string()
    } else {
        words.join(" ")
    }
}

/// Opens the stable per-MD5 lock. Writers have exclusive access.
pub(super) fn lock_binary(project_dir: &Path, exclusive: bool) -> Result<File> {
    fs::create_dir_all(project_dir)?;
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
    let computed = format!("{:x}", hasher.finalize());
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
            Err(_) => Ok(None),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Selects how `analyzeHeadless` opens or imports the target session.
#[derive(Debug, Clone)]
pub enum LaunchMode {
    /// Import a persisted binary with optional processor, compiler, loader, and base address.
    ImportBinary {
        /// Launch path to the persisted binary (`binary` or `binary.<ext>`).
        input_path: PathBuf,
        /// Validated import flags.
        options: ImportOptions,
    },
    /// Open a saved internal or attached `.gpr` project with `OpenSavedProject.java`.
    OpenSaved {
        /// True when the target is an external `.gpr` project.
        attached_gpr: bool,
        /// Optional target program name or project path.
        program_name: Option<String>,
        /// Crash recovery backup directory under `projects/<md5>/`.
        backup_dir: PathBuf,
    },
}

/// All the data that the daemon needs to launch Ghidra for one session.
#[derive(Debug, Clone)]
pub struct PreparedProject {
    /// The 32-hex session identifier.
    pub md5: String,
    /// The display file name.
    pub file_name: String,
    /// The project root for `analyzeHeadless`. On Unix, it is a non-hidden alias.
    pub ghidra_launch_root: PathBuf,
    /// The Ghidra project name (`project` for binaries, `<stem>` for `.gpr`).
    pub ghidra_project_name: String,
    /// A new 256-bit bridge credential for this launch.
    pub agent_token: String,
    /// Import vs saved-project launch mode.
    pub launch_mode: LaunchMode,
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

    /// Returns `true` when this launch performs a fresh binary import.
    pub fn is_fresh_binary_import(&self) -> bool {
        matches!(self.launch_mode, LaunchMode::ImportBinary { .. })
    }
}

/// Prepares the launch of Ghidra for a saved binary or an attached `.gpr` project.
///
/// # Errors
///
/// Fails if the binary or `.gpr` project is absent, locked, or corrupted.
pub fn prepare_project(paths: &McpPaths, md5: &str) -> Result<PreparedProject> {
    paths.ensure_layout()?;
    let md5 = normalize_md5(md5)?;
    let project_dir = paths.project_dir(&md5);
    let _lock = lock_binary(&project_dir, false)?;

    if let Some(attached) = gpr::read_attached_metadata(paths, &md5)? {
        return gpr::prepare_attached_gpr(paths, &md5, attached);
    }

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

    let existing_project =
        ghidra_root.join("project.gpr").is_file() && ghidra_root.join("project.rep").is_dir();
    let saved_name = if project_dir.join(metadata.effective_saved_name()).is_file() {
        metadata.effective_saved_name()
    } else {
        BINARY_NAME.to_string()
    };
    let has_binary = project_dir.join(&saved_name).is_file();
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

    let launch_mode = if existing_project {
        LaunchMode::OpenSaved {
            attached_gpr: false,
            program_name: None,
            backup_dir: paths.recovery_backups_dir(&md5),
        }
    } else {
        metadata.import_options.validate_complete()?;
        LaunchMode::ImportBinary {
            input_path: paths.binary_launch_file(&md5, &saved_name),
            options: metadata.import_options,
        }
    };

    Ok(PreparedProject {
        ghidra_launch_root: paths.ghidra_launch_root(&md5),
        ghidra_project_name: INTERNAL_PROJECT_NAME.to_string(),
        file_name: metadata.file_name,
        agent_token: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        launch_mode,
        md5,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::SystemTime;

    /// Builds isolated [`McpPaths`] inside `root` without hidden segments.
    fn test_paths(root: &Path) -> McpPaths {
        let paths = McpPaths {
            config_toml: root.join("config.toml"),
            projects_dir: root.join("projects"),
            runtime_dir: root.join("run"),
            tmp_dir: root.join("run").join("tmp"),
        };
        paths.ensure_layout().unwrap();
        paths
    }

    /// Collects file sizes and modification timestamps across `dir`.
    fn snapshot_tree(dir: &Path) -> BTreeMap<PathBuf, (u64, SystemTime)> {
        let mut out = BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(current) = stack.pop() {
            for entry in fs::read_dir(&current).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let meta = fs::symlink_metadata(&path).unwrap();
                if meta.is_dir() {
                    stack.push(path);
                } else {
                    out.insert(path, (meta.len(), meta.modified().unwrap()));
                }
            }
        }
        out
    }

    /// Checks that firmware extensions remain on the import path and options persist.
    #[test]
    fn keeps_sanitized_firmware_extensions_and_options() {
        let root = tempfile::tempdir().unwrap();
        let paths = test_paths(root.path());
        for (index, file_name, expected_ext, expected_loader) in [
            (1u8, "STM32.BIN", "binary.bin", None),
            (2u8, "boot.HEX", "binary.hex", None),
            (3u8, "app.IHEX", "binary.ihex", None),
            (
                4u8,
                "motorola.SREC",
                "binary.srec",
                Some("MotorolaHexLoader"),
            ),
            (5u8, "app.elf", "binary", None),
        ] {
            let bytes = [index; 16];
            let md5 = format!("{:x}", md5::compute(bytes));
            let source = root.path().join(file_name);
            fs::write(&source, bytes).unwrap();
            let opts = ImportOptions::from_raw(
                Some("ARM:LE:32:Cortex"),
                Some("default"),
                None,
                Some("08000000"),
            )
            .unwrap();
            persist_binary_with_options(&paths, &source, &md5, file_name, &opts, false).unwrap();
            let prepared = prepare_project(&paths, &md5).unwrap();
            let LaunchMode::ImportBinary {
                input_path,
                options,
            } = prepared.launch_mode
            else {
                panic!("expected ImportBinary mode");
            };
            assert_eq!(
                input_path.file_name().unwrap().to_str().unwrap(),
                expected_ext
            );
            assert_eq!(options.processor.as_deref(), Some("ARM:LE:32:Cortex"));
            assert_eq!(options.compiler_spec.as_deref(), Some("default"));
            assert_eq!(options.base_address.as_deref(), Some("0x08000000"));
            assert_eq!(options.effective_loader(&input_path), expected_loader);
        }

        let lebe = ImportOptions::from_raw(
            Some("ARM:LEBE:32:v8LEInstruction"),
            None,
            Some("ghidra.app.util.opinion.BinaryLoader"),
            Some("ram:08004000"),
        )
        .unwrap();
        assert_eq!(
            lebe.processor.as_deref(),
            Some("ARM:LEBE:32:v8LEInstruction")
        );
        assert_eq!(lebe.loader.as_deref(), Some("BinaryLoader"));
        assert_eq!(lebe.base_address.as_deref(), Some("ram:0x08004000"));

        let saved_md5 = format!("{:x}", md5::compute([9u8; 16]));
        let saved_src = root.path().join("saved.bin");
        fs::write(&saved_src, [9u8; 16]).unwrap();
        let initial =
            ImportOptions::from_raw(Some("ARM:LE:32:Cortex"), None, None, Some("08000000"))
                .unwrap();
        persist_binary_with_options(&paths, &saved_src, &saved_md5, "saved.bin", &initial, false)
            .unwrap();
        let ghidra_root = paths.ghidra_project_root(&saved_md5);
        fs::create_dir_all(ghidra_root.join("project.rep")).unwrap();
        fs::write(ghidra_root.join("project.gpr"), "<project/>").unwrap();

        let conflicting =
            ImportOptions::from_raw(Some("ARM:LE:32:Cortex"), None, None, Some("08004000"))
                .unwrap();
        let conflict_err =
            update_binary_import_options(&paths, &saved_md5, &conflicting, false).unwrap_err();
        assert!(conflict_err.to_string().contains("reimport=true"));
        update_binary_import_options(&paths, &saved_md5, &conflicting, true).unwrap();
    }

    /// Checks deterministic 32-hex `.gpr` IDs, non-hidden aliases, and zero-mutation lock errors.
    #[test]
    fn attaches_hidden_gpr_and_rejects_locked_project_without_changes() {
        let root = tempfile::tempdir().unwrap();
        let paths = test_paths(root.path());
        let hidden_dir = root.path().join(".hidden-ghidra").join("board");
        fs::create_dir_all(hidden_dir.join("firmware.rep")).unwrap();
        let gpr_file = hidden_dir.join("firmware.gpr");
        fs::write(&gpr_file, "<project/>").unwrap();

        let gpr_first = resolve_gpr_path(&gpr_file).unwrap();
        let gpr_second = resolve_gpr_path(&gpr_file).unwrap();
        assert_eq!(gpr_first.md5, gpr_second.md5);
        assert_eq!(gpr_first.md5.len(), 32);
        assert!(gpr_first.md5.bytes().all(|b| b.is_ascii_hexdigit()));

        persist_attached_gpr(&paths, &gpr_first, Some("bootloader")).unwrap();
        let prepared = prepare_project(&paths, &gpr_first.md5).unwrap();
        #[cfg(unix)]
        {
            for part in prepared.ghidra_launch_root.components() {
                if let std::path::Component::Normal(segment) = part {
                    assert!(
                        !segment.to_string_lossy().starts_with('.'),
                        "launch path has hidden segment: {}",
                        prepared.ghidra_launch_root.display()
                    );
                }
            }
        }
        assert_eq!(prepared.ghidra_project_name, "firmware");

        // Place a Ghidra `.lock` file and verify zero project file mutations on lock rejection.
        let lock_path = hidden_dir.join("firmware.lock");
        fs::write(&lock_path, "Project lock").unwrap();
        let before = snapshot_tree(&hidden_dir);
        let err = check_gpr_not_locked(&gpr_first).unwrap_err();
        assert!(err.to_string().contains("locked"), "{err}");
        let after = snapshot_tree(&hidden_dir);
        assert_eq!(before, after);
    }
}
