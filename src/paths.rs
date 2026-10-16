// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The locations of all files: the persistent home and the runtime directory.
//!
//! - The **persistent home** (`GHIDRA_MCP_HOME`, default `~/.ghidra-mcp`, or
//!   `%LOCALAPPDATA%\ghidra-mcp` on Windows) contains `config.toml`, and one
//!   directory for each saved binary in `projects/<md5>/`.
//! - The **runtime directory** contains files that you can delete: the daemon
//!   control files, the session snapshots, the logs, the bridge files and the
//!   temporary files. On Unix, it is `ghidra-mcp-<uid>` in the runtime or
//!   temporary directory of the system. On Windows, it is
//!   `%LOCALAPPDATA%\ghidra-mcp\run`.
//!
//! The daemon always makes sure that the runtime directory is a real directory
//! that the current user owns, with the mode `0700`. Then other users cannot
//! read files in it or put files in it. The control files of the daemon need this protection.
//!
//! On Unix, Ghidra refuses a project path with a hidden segment (a segment that
//! starts with `.`). But the default home is hidden. For this reason, the
//! daemon gives Ghidra the **project launch alias** `<runtime>/projects`. This
//! alias is a symbolic link to the `projects/` directory of the persistent home.
//! The runtime directory has no hidden segments.

use anyhow::{ensure, Context, Result};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The name of the persistent home in the home directory or the `LocalAppData`
/// directory of the user.
#[cfg(unix)]
const HOME_DIR_NAME: &str = ".ghidra-mcp";
/// The name of the persistent home in the home directory or the `LocalAppData`
/// directory of the user.
#[cfg(windows)]
const HOME_DIR_NAME: &str = "ghidra-mcp";

/// The directories and files that the daemon uses.
#[derive(Debug, Clone)]
pub struct McpPaths {
    /// The user configuration in the persistent home.
    pub config_toml: PathBuf,
    /// The project directories of the binaries in the persistent home, with the MD5 as name.
    pub projects_dir: PathBuf,
    /// The private runtime directory.
    pub runtime_dir: PathBuf,
    /// The temporary files, the uploads, and `java.io.tmpdir` of Java.
    pub tmp_dir: PathBuf,
}

impl McpPaths {
    /// Finds the persistent home and makes the runtime directory.
    ///
    /// # Errors
    ///
    /// Fails if the daemon cannot find a home or make the runtime directory.
    /// Also fails if the runtime directory is not private.
    pub fn new() -> Result<Self> {
        let home = ghidra_mcp_home()?;
        let runtime_dir = runtime_dir()?;
        Ok(Self {
            config_toml: home.join("config.toml"),
            projects_dir: home.join("projects"),
            tmp_dir: runtime_dir.join("tmp"),
            runtime_dir,
        })
    }

    /// Makes the directory layout and, on Unix, the project launch alias.
    /// A second call restores absent items.
    ///
    /// # Errors
    ///
    /// Fails if the daemon cannot make a directory.
    /// Also fails if a different object occupies the path of the alias.
    pub fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(&self.projects_dir)?;
        ensure_runtime_directory(&self.runtime_dir)?;
        fs::create_dir_all(&self.tmp_dir)?;
        #[cfg(unix)]
        ensure_project_link(self)?;
        Ok(())
    }

    /// Returns the persistent directory of one binary: `binary`, `binary.json` and `ghidra/`.
    pub fn project_dir(&self, md5: &str) -> PathBuf {
        self.projects_dir.join(md5)
    }

    /// Returns the physical Ghidra project root (`project.gpr` and `project.rep`).
    pub fn ghidra_project_root(&self, md5: &str) -> PathBuf {
        self.project_dir(md5).join("ghidra")
    }

    /// Returns the Ghidra project root that the daemon gives to Ghidra: the launch
    /// alias on Unix, and the physical path on Windows.
    pub fn ghidra_launch_root(&self, md5: &str) -> PathBuf {
        self.launch_project_dir(md5).join("ghidra")
    }

    /// Returns the path of the saved binary that the daemon gives to Ghidra for the import.
    pub fn binary_launch_path(&self, md5: &str) -> PathBuf {
        self.launch_project_dir(md5).join("binary")
    }

    /// Returns the project directory of a binary as Ghidra sees it.
    fn launch_project_dir(&self, md5: &str) -> PathBuf {
        #[cfg(unix)]
        {
            self.runtime_dir.join("projects").join(md5)
        }
        #[cfg(windows)]
        {
            self.project_dir(md5)
        }
    }

    /// Returns the directory of the session snapshots, with one subdirectory for each MD5.
    pub fn sessions_dir(&self) -> PathBuf {
        self.runtime_dir.join("sessions")
    }

    /// Returns the path of the runtime snapshot of a session.
    pub fn session_json(&self, md5: &str) -> PathBuf {
        self.sessions_dir().join(md5).join("session.json")
    }

    /// Returns the path of the log of the Ghidra standard output of a session.
    pub fn stdout_log(&self, md5: &str) -> PathBuf {
        self.runtime_dir.join("logs").join(md5).join("stdout.log")
    }

    /// Returns the path of the log of the Ghidra standard error of a session.
    pub fn stderr_log(&self, md5: &str) -> PathBuf {
        self.runtime_dir.join("logs").join(md5).join("stderr.log")
    }
}

/// Replaces `path` with `bytes`. A reader sees the old or the new contents,
/// never a partial write. Publication synchronizes the file.
/// It also requests durable directory entries on supported platforms.
///
/// # Errors
///
/// Fails if the daemon cannot make the parent directory.
/// Also fails if a write, synchronization, or rename operation fails.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing parent directory")?;
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating a temporary file in {}", parent.display()))?;
    file.write_all(bytes)?;
    persist_synced(file, path)
}

/// Synchronizes a staged file and atomically replaces `path` on the same file system.
/// Unix also synchronizes the parent directory.
/// Windows requests a write-through move.
/// A failure only removes the temporary path, never a published destination.
///
/// # Errors
///
/// Fails if a file or directory synchronization or publication fails.
pub fn persist_synced(file: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    let parent = path.parent().context("missing parent directory")?;
    file.as_file().sync_all()?;
    #[cfg(unix)]
    file.persist(path)
        .with_context(|| format!("replacing {}", path.display()))?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MoveFileExW, SetFileAttributesW, FILE_ATTRIBUTE_NORMAL, MOVEFILE_REPLACE_EXISTING,
            MOVEFILE_WRITE_THROUGH,
        };
        let source: Vec<u16> = file
            .path()
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let destination: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: The buffers are valid, NUL-terminated paths. The source is our
        // temporary file. Its handle permits deletion, as NamedTempFile requires.
        if unsafe { SetFileAttributesW(source.as_ptr(), FILE_ATTRIBUTE_NORMAL) } == 0 {
            return Err(std::io::Error::last_os_error()).context("setting saved file attributes");
        }
        file.as_file().sync_all()?;
        // SAFETY: Both buffers stay alive during the call. The temporary file is on
        // the destination's file system, so this is a rename rather than a copy.
        if unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("replacing {}", path.display()));
        }
        drop(file);
    }
    sync_directory(parent)
}

/// Synchronizes directory entries on Unix. Windows file publication uses write-through moves.
///
/// # Errors
///
/// Fails if the function cannot open or synchronize the Unix directory.
#[cfg_attr(
    windows,
    expect(
        clippy::unnecessary_wraps,
        reason = "shared fallible API; Windows publication uses write-through moves"
    )
)]
pub fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("fsync {}", path.display()))?;
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

/// Finds `GHIDRA_MCP_HOME`. The default is `$HOME/.ghidra-mcp` on Unix and
/// `LocalAppData/ghidra-mcp` on Windows.
fn ghidra_mcp_home() -> Result<PathBuf> {
    if let Some(home) = env::var_os("GHIDRA_MCP_HOME") {
        return Ok(crate::java_path::java_path(Path::new(&home))?);
    }
    #[cfg(unix)]
    {
        let home =
            env::var_os("HOME").context("GHIDRA_MCP_HOME is not set and HOME is unavailable")?;
        Ok(PathBuf::from(home).join(HOME_DIR_NAME))
    }
    #[cfg(windows)]
    {
        windows_data_dir()
    }
}

/// Returns the private runtime directory of the user. If necessary, it makes the directory.
///
/// On Unix, the directory is `ghidra-mcp-<uid>` in `XDG_RUNTIME_DIR` or in the
/// temporary directory. If that path has a hidden segment, the directory is in `/tmp`.
///
/// # Errors
///
/// Fails if the daemon cannot make the directory. Also fails if the path is a
/// symbolic link, is not a directory, or belongs to another user.
pub fn runtime_dir() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        let base = dirs::runtime_dir().unwrap_or_else(env::temp_dir);
        fs::create_dir_all(&base)?;
        // Ghidra refuses dot segments in a path. For this reason, normalize
        // the path before you make the alias.
        let base = fs::canonicalize(base)?;
        // Ghidra also refuses hidden segments.
        let base = if has_hidden_component(&base) {
            PathBuf::from("/tmp")
        } else {
            base
        };
        let run = base.join(format!("ghidra-mcp-{}", current_uid()));
        ensure_private_directory(&run)?;
        Ok(run)
    }
    #[cfg(windows)]
    {
        let run = windows_data_dir()?.join("run");
        ensure_runtime_directory(&run)?;
        Ok(run)
    }
}

/// Returns the default persistent home on Windows, `%LOCALAPPDATA%\ghidra-mcp`.
#[cfg(windows)]
fn windows_data_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir().context("Windows LocalAppData is unavailable")?;
    Ok(crate::java_path::java_path(&base.join(HOME_DIR_NAME))?)
}

/// Makes a runtime directory and its parents again, and keeps it private.
fn ensure_runtime_directory(path: &Path) -> Result<()> {
    let parent = path.parent().context("runtime directory has no parent")?;
    fs::create_dir_all(parent)?;
    ensure_private_directory(path)
}

/// Returns `true` if a segment of `path` starts with `.`.
#[cfg(unix)]
fn has_hidden_component(path: &Path) -> bool {
    path.components().any(|part| {
        matches!(
          part,
          std::path::Component::Normal(name) if name.to_string_lossy().starts_with('.')
        )
    })
}

/// Returns the effective user ID of this process.
#[cfg(unix)]
pub fn current_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Makes a directory with the mode `0700`. If the directory exists, it makes
/// sure that it is a real directory of the current user, and sets its mode to `0700`.
fn ensure_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "runtime directory is not a real directory: {}",
                path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    metadata.uid() == current_uid(),
                    "runtime directory belongs to another user: {}",
                    path.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            let created = {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(path)
            };
            #[cfg(windows)]
            let created = fs::DirBuilder::new().create(path);
            match created {
                Ok(()) => {}
                // Another process made the path first. Examine the object at the path.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return ensure_private_directory(path);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Makes the project launch alias: `<runtime>/projects` points to the
/// persistent `projects/`. If another file occupies the path or points to a
/// different target, the function fails. It never replaces the path, because it
/// can be the alias of another daemon.
#[cfg(unix)]
fn ensure_project_link(paths: &McpPaths) -> Result<()> {
    let link = paths.runtime_dir.join("projects");
    let target = fs::canonicalize(&paths.projects_dir)?;
    match fs::symlink_metadata(&link) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_symlink() && fs::read_link(&link)? == target,
                "runtime projects path is occupied or links to another directory: {}",
                link.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::os::unix::fs::symlink(&target, &link) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return ensure_project_link(paths);
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
