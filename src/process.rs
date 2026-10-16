// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Ghidra child processes: start them, and stop their full process tree.
//!
//! `analyzeHeadless` is a script that starts a JVM. For this reason, it is not sufficient to
//! stop the direct child:
//!
//! - **Unix**: The child is the leader of a new process group. The daemon sends
//!   signals to that group. If the daemon itself stops, the bridge sees the
//!   closed connection. Then Ghidra saves the program and exits.
//! - **Windows**: The daemon starts the child in the suspended state in a job object.
//!   The job object kills all its processes when its last handle closes.
//!   See `windows_job`. Only the daemon has that handle.
//!   Thus, the process tree stops with the daemon.

#[cfg(windows)]
/// Owns the Windows job that stops all descendants with the daemon.
mod windows_job {
  use std::io;
  use std::mem::size_of;
  use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
  use std::os::windows::process::CommandExt;
  use std::process::{Child, Command};
  use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    System::{
      Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
      },
      JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
      },
      Threading::{
        OpenThread, ResumeThread, CREATE_NO_WINDOW, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
      },
    },
  };

  /// A job object that holds the process tree of one child and kills it on close.
  #[derive(Debug)]
  pub struct WindowsJob(OwnedHandle);

  impl WindowsJob {
    /// Starts `command` in a new job, before the command runs any code.
    ///
    /// # Errors
    ///
    /// Fails if the daemon cannot make or configure the job.
    /// Also fails if the daemon cannot start, assign, or resume the child.
    /// The daemon kills the child after an assignment or resume failure.
    pub fn spawn(command: &mut Command) -> io::Result<(Child, Self)> {
      // SAFETY: A null security attribute and a null name are valid. They make an
      // anonymous job with a handle that is not inheritable.
      let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
      if handle.is_null() {
        return Err(io::Error::last_os_error());
      }
      // SAFETY: `handle` is a valid job handle, and no other object owns it.
      let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });

      let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
      limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
      let limits_size = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
        .expect("job limit structure fits in u32");
      // SAFETY: The pointer and the size describe `limits`. `limits` lives longer than
      // the call and has the layout that `JobObjectExtendedLimitInformation` needs.
      let configured = unsafe {
        SetInformationJobObject(
          job.0.as_raw_handle(),
          JobObjectExtendedLimitInformation,
          (&raw const limits).cast(),
          limits_size,
        )
      };
      if configured == 0 {
        return Err(io::Error::last_os_error());
      }

      // cmd.exe must not start its Java child before cmd.exe is in the job.
      command.creation_flags(CREATE_NO_WINDOW | CREATE_SUSPENDED);
      let mut child = command.spawn()?;
      // SAFETY: Both handles are valid. `job` and `child` own them.
      let assigned =
        unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), child.as_raw_handle()) };
      let result = if assigned == 0 {
        Err(io::Error::last_os_error())
      } else {
        resume_initial_thread(child.id())
      };
      if let Err(error) = result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
      }
      Ok((child, job))
    }

    /// Stops all processes in the job.
    pub fn terminate(&self) {
      // SAFETY: The handle is a valid job handle, and `self` owns it.
      let _ = unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) };
    }
  }

  /// Resumes the only thread of a process that started in the suspended state.
  ///
  /// Stable std gives the process handle, but not the handle of its primary
  /// thread. For this reason, the function finds the thread in a `ToolHelp`
  /// snapshot. A suspended process did not run code. For this reason, it has only one thread.
  fn resume_initial_thread(pid: u32) -> io::Result<()> {
    // SAFETY: Makes a snapshot of all threads. The call has no pointer arguments.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
      return Err(io::Error::last_os_error());
    }
    // SAFETY: `snapshot` is a valid handle, and no other object owns it.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot) };
    let mut entry = THREADENTRY32 {
      dwSize: u32::try_from(size_of::<THREADENTRY32>()).expect("thread entry fits in u32"),
      ..Default::default()
    };
    // SAFETY: `entry` is a valid `THREADENTRY32`, and `dwSize` has the necessary value.
    let mut present = unsafe { Thread32First(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    while present {
      if entry.th32OwnerProcessID == pid {
        // SAFETY: Opens a thread by its ID. The call has no pointer arguments.
        let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
        if thread.is_null() {
          return Err(io::Error::last_os_error());
        }
        // SAFETY: `thread` is a valid handle, and no other object owns it.
        let thread = unsafe { OwnedHandle::from_raw_handle(thread) };
        // SAFETY: The handle has the `THREAD_SUSPEND_RESUME` access right.
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
          return Err(io::Error::last_os_error());
        }
        return Ok(());
      }
      // SAFETY: The same as for `Thread32First`.
      present = unsafe { Thread32Next(snapshot.as_raw_handle(), &raw mut entry) } != 0;
    }
    Err(io::Error::new(
      io::ErrorKind::NotFound,
      "suspended process thread was not found",
    ))
  }
}

use anyhow::Result;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The interval at which a wait that blocks examines the child.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A child process, and on Windows the job that holds its process tree.
#[derive(Debug)]
pub struct ManagedChild {
  /// The direct child, `analyzeHeadless`.
  child: Option<Child>,
  /// Owns the process tree of the child.
  #[cfg(windows)]
  job: Option<windows_job::WindowsJob>,
  /// The process group ID of the child on Unix.
  #[cfg(unix)]
  pgid: Option<libc::pid_t>,
  /// Stops double cleanup in Drop when explicitly reaped.
  cleaned_up: bool,
}

impl Drop for ManagedChild {
  fn drop(&mut self) {
    if self.cleaned_up {
      return;
    }
    self.cleanup();
    if let Some(mut child) = self.child.take() {
      match child.try_wait() {
        Ok(Some(_)) => {}
        _ => {
          // The child still runs. Start a background thread that waits for it
          // and stops zombie processes.
          std::thread::spawn(move || {
            let _ = child.wait();
          });
        }
      }
    }
  }
}

impl ManagedChild {
  /// Starts `command`. On Unix, the child is the leader of a new process
  /// group. On Windows, it starts in a new job.
  ///
  /// # Errors
  ///
  /// Fails if the daemon cannot make the child, or on Windows its job.
  pub fn spawn(command: &mut Command) -> Result<Self> {
    #[cfg(windows)]
    {
      let (child, job) = windows_job::WindowsJob::spawn(command)?;
      Ok(Self {
        child: Some(child),
        job: Some(job),
        cleaned_up: false,
      })
    }
    #[cfg(unix)]
    {
      use std::os::unix::process::CommandExt;
      command.process_group(0);
      let child = command.spawn()?;
      let pgid = libc::pid_t::try_from(child.id()).ok();
      Ok(Self {
        child: Some(child),
        pgid,
        cleaned_up: false,
      })
    }
  }

  /// Takes the standard output pipe of the child.
  pub fn take_stdout(&mut self) -> Option<ChildStdout> {
    self.child.as_mut().and_then(|c| c.stdout.take())
  }

  /// Takes the standard error pipe of the child.
  pub fn take_stderr(&mut self) -> Option<ChildStderr> {
    self.child.as_mut().and_then(|c| c.stderr.take())
  }

  /// Examines if the child stopped, without a wait. On Windows, if the child
  /// stopped, this function releases its job. Then the job stops the processes
  /// of the tree that still run.
  ///
  /// # Errors
  ///
  /// Fails if the daemon cannot read the exit status.
  pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
    let status = match self.child.as_mut() {
      Some(c) => c.try_wait()?,
      None => return Ok(None),
    };
    #[cfg(windows)]
    if status.is_some() {
      self.job.take();
    }
    Ok(status)
  }

  /// Waits a maximum of `timeout` for the child and its process tree to stop.
  /// Returns `true` if it stopped.
  fn wait_timeout(&mut self, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
      let child_stopped = self.try_wait().ok().flatten().is_some();
      #[cfg(unix)]
      let tree_stopped = child_stopped && self.pgid.is_none_or(|pgid| !is_group_alive(pgid));
      #[cfg(not(unix))]
      let tree_stopped = child_stopped;

      if tree_stopped {
        return true;
      }
      if Instant::now() >= deadline {
        return false;
      }
      std::thread::sleep(POLL_INTERVAL);
    }
  }

  /// Stops the process tree in steps:
  ///
  /// 1. It waits `grace` for the tree to stop by itself.
  /// 2. It tells the tree to stop, and waits `terminate_timeout`.
  /// 3. It kills the tree, and waits `kill_timeout`.
  /// 4. It waits with no time limit.
  ///
  /// This function blocks the thread. Run it with `spawn_blocking`.
  pub fn reap_or_kill(
    mut self,
    grace: Duration,
    terminate_timeout: Duration,
    kill_timeout: Duration,
  ) {
    if self.wait_timeout(grace) {
      self.cleaned_up = true;
      return;
    }
    #[cfg(unix)]
    if let Some(pgid) = self.pgid {
      signal_group(pgid, libc::SIGTERM);
    }
    #[cfg(windows)]
    self.terminate_job();
    if self.wait_timeout(terminate_timeout) {
      self.cleaned_up = true;
      return;
    }
    #[cfg(unix)]
    if let Some(pgid) = self.pgid {
      signal_group(pgid, libc::SIGKILL);
    }
    // A job has no softer signal. The second request also stops processes that started late.
    #[cfg(windows)]
    self.terminate_job();
    if self.wait_timeout(kill_timeout) {
      self.cleaned_up = true;
      return;
    }
    self.cleanup();
    if let Some(mut child) = self.child.take() {
      let _ = child.wait();
    }
  }

  /// Stops the child process tree. Drop does not repeat the action.
  fn cleanup(&mut self) {
    self.cleaned_up = true;
    #[cfg(windows)]
    self.terminate_job();
    #[cfg(unix)]
    if let Some(pgid) = self.pgid {
      // SAFETY: kill has no memory-safety preconditions.
      unsafe {
        libc::kill(-pgid, libc::SIGKILL);
      }
    }
  }

  /// Stops all processes in the job of the child.
  #[cfg(windows)]
  fn terminate_job(&self) {
    if let Some(job) = &self.job {
      job.terminate();
    }
  }
}

/// Sends `signal` to the process group that `pgid` leads.
#[cfg(unix)]
fn signal_group(pgid: libc::pid_t, signal: libc::c_int) {
  // SAFETY: `kill` has no memory-safety preconditions. The group belongs to our
  // child, and the daemon did not reap the child. Then no other process has the ID.
  unsafe {
    libc::kill(-pgid, signal);
  }
}

/// Returns `true` if any process in the process group `pgid` is alive.
#[cfg(unix)]
fn is_group_alive(pgid: libc::pid_t) -> bool {
  // SAFETY: `kill` with signal 0 checks if the process group exists. It sends no signal.
  unsafe { libc::kill(-pgid, 0) == 0 }
}

/// Default maximum size for a log file before rotation: 10 MiB (10 * 1024 * 1024 bytes).
pub const DEFAULT_MAX_LOG_SIZE: u64 = 10 * 1024 * 1024;

/// Default number of retained backup log generations: 3 generations (.1, .2, .3).
pub const DEFAULT_MAX_LOG_BACKUPS: usize = 3;

/// Placeholder text that replaces sensitive authentication tokens in logs.
pub const REDACTED_TOKEN_PLACEHOLDER: &str = "[REDACTED_TOKEN]";

/// Returns the path of a numbered backup, for example `path.1` or `path.2`.
fn compute_backup_path(path: &Path, generation: usize) -> PathBuf {
  let mut file_name = path.file_name().unwrap_or_default().to_os_string();
  file_name.push(format!(".{generation}"));
  path.with_file_name(file_name)
}

/// Shifts backup files (.1 -> .2 -> .3) and removes generations above `max_backups`.
fn shift_backups(path: &Path, max_backups: usize) -> io::Result<()> {
  // Old configurations can leave gaps or more generations than the current limit.
  if let Some(parent) = path
    .parent()
    .filter(|parent| !parent.as_os_str().is_empty())
  {
    let prefix = format!(
      "{}.",
      path.file_name().unwrap_or_default().to_string_lossy()
    );
    for entry in fs::read_dir(parent)? {
      let entry = entry?;
      let name = entry.file_name();
      if name
        .to_string_lossy()
        .strip_prefix(&prefix)
        .and_then(|suffix| suffix.parse::<usize>().ok())
        .is_some_and(|generation| generation > max_backups)
      {
        fs::remove_file(entry.path())?;
      }
    }
  }
  if !path.exists() {
    return Ok(());
  }

  if max_backups == 0 {
    fs::remove_file(path)?;
    return Ok(());
  }

  // Remove the oldest retained generation if it exists.
  let oldest = compute_backup_path(path, max_backups);
  if oldest.exists() {
    let _ = fs::remove_file(&oldest);
  }

  // Shift backups in reverse order: (max_backups - 1) down to 1.
  for i in (1..max_backups).rev() {
    let src = compute_backup_path(path, i);
    let dst = compute_backup_path(path, i + 1);
    if src.exists() {
      if dst.exists() {
        let _ = fs::remove_file(&dst);
      }
      fs::rename(&src, &dst)?;
    }
  }

  // Move the active log file to .1.
  let backup_1 = compute_backup_path(path, 1);
  if backup_1.exists() {
    let _ = fs::remove_file(&backup_1);
  }
  fs::rename(path, &backup_1)?;

  Ok(())
}

/// A log writer with rotation. It limits file size, shifts backup
/// generations, redacts tokens, and closes file handles before rotation.
#[derive(Debug)]
pub struct RollingLogWriter {
  /// The active log path, for example `stdout.log` or `stderr.log`.
  path: PathBuf,
  /// Active file write handle. A `None` value closes the handle before a file rename.
  file: Option<File>,
  /// Current size in bytes of the active log file.
  current_size: u64,
  /// Maximum size in bytes before file rotation.
  max_size: u64,
  /// Maximum number of backup generations retained (0 means no backups).
  max_backups: usize,
  /// Sensitive authentication token to redact on line boundaries.
  token: String,
}

impl RollingLogWriter {
  /// Creates a new log writer with the specified limits and a redaction token.
  ///
  /// If the target file exists, the function gets its size from
  /// file metadata. The function creates absent parent directories.
  ///
  /// # Errors
  ///
  /// Fails if parent directory creation or target file access fails.
  pub fn new(path: PathBuf, max_size: u64, max_backups: usize, token: String) -> io::Result<Self> {
    if max_size == 0 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "log size limit must be positive",
      ));
    }
    if let Some(parent) = path
      .parent()
      .filter(|parent| !parent.as_os_str().is_empty())
    {
      fs::create_dir_all(parent)?;
    }
    Self::rotate_if_exceeds(&path, max_size, max_backups)?;

    let current_size = if path.exists() {
      fs::metadata(&path)?.len()
    } else {
      0
    };

    let file = open_log_file(&path)?;

    Ok(Self {
      path,
      file: Some(file),
      current_size,
      max_size,
      max_backups,
      token,
    })
  }

  /// Creates a new log writer with default parameters (10 MiB limit, 3 backups).
  ///
  /// # Errors
  ///
  /// Fails if parent directory creation or target file access fails.
  pub fn new_with_defaults(path: PathBuf, token: String) -> io::Result<Self> {
    Self::new(path, DEFAULT_MAX_LOG_SIZE, DEFAULT_MAX_LOG_BACKUPS, token)
  }

  /// Writes one log line through the redaction and rotation steps.
  ///
  /// If `token` is not empty, the writer replaces each occurrence in `line`
  /// with `[REDACTED_TOKEN]`. The line ends with `\n`.
  ///
  /// # Errors
  ///
  /// Fails if rotation or a write to the target file fails.
  pub fn write_line(&mut self, line: &str) -> io::Result<()> {
    let redacted = if self.token.is_empty() {
      line.to_string()
    } else {
      line.replace(&self.token, REDACTED_TOKEN_PLACEHOLDER)
    };

    let formatted = if redacted.ends_with('\n') {
      redacted
    } else {
      format!("{redacted}\n")
    };

    // Redact before truncation so that a token at the size boundary stays private.
    let mut formatted = formatted;
    if u64::try_from(formatted.len()).unwrap_or(u64::MAX) > self.max_size {
      let limit = usize::try_from(self.max_size)
        .unwrap_or(usize::MAX)
        .saturating_sub(1);
      let mut end = limit.min(formatted.len());
      while !formatted.is_char_boundary(end) {
        end -= 1;
      }
      formatted.truncate(end);
      formatted.push('\n');
    }
    let bytes = formatted.as_bytes();
    let bytes_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);

    if self.current_size.saturating_add(bytes_len) > self.max_size && self.current_size > 0 {
      self.rotate()?;
    }

    if self.file.is_none() {
      let file = open_log_file(&self.path)?;
      self.file = Some(file);
    }

    if let Some(file) = &mut self.file {
      file.write_all(bytes)?;
      file.flush()?;
      self.current_size = self.current_size.saturating_add(bytes_len);
    }

    Ok(())
  }

  /// Rotates the active log file and shifts older generations (.1 -> .2 -> .3).
  ///
  /// On Windows, the writer flushes and drops the handle before a rename.
  /// This sequence stops file-share violations.
  ///
  /// # Errors
  ///
  /// Fails if an I/O error occurs during a file rename, deletion, or new open operation.
  pub fn rotate(&mut self) -> io::Result<()> {
    if !self.path.exists() {
      return Ok(());
    }

    // Flush and drop the active handle before a rename or deletion.
    if let Some(mut file) = self.file.take() {
      file.flush()?;
      drop(file);
    }

    shift_backups(&self.path, self.max_backups)?;

    let file = open_log_file(&self.path)?;
    self.file = Some(file);
    self.current_size = 0;
    Ok(())
  }

  /// Inspects `path` and rotates it if its size is at least `max_size`.
  /// Does not rotate an empty file. Also rotates its backup generations.
  ///
  /// # Errors
  ///
  /// Fails if a metadata query or file shift causes an I/O error.
  pub fn rotate_if_exceeds(path: &Path, max_size: u64, max_backups: usize) -> io::Result<()> {
    if !path.exists() {
      return Ok(());
    }
    let metadata = fs::metadata(path)?;
    let len = metadata.len();
    if len >= max_size && len > 0 {
      shift_backups(path, max_backups)?;
    }
    Ok(())
  }
}

/// Opens a private log file, also after rotation. On Unix, it sets the file
/// mode to `0600`, also for a current file.
fn open_log_file(path: &Path) -> io::Result<File> {
  let mut options = OpenOptions::new();
  options.create(true).append(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
  }
  let file = options.open(path)?;
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
  }
  Ok(file)
}

/// Copies the output of a child to `log_path` on a background thread. It
/// replaces `token` with a placeholder. Then the bridge credential never goes
/// into a log. The thread stops when the child closes its end of the pipe.
pub fn spawn_log_forwarder(reader: impl Read + Send + 'static, log_path: PathBuf, token: String) {
  spawn_log_forwarder_bounded(
    reader,
    log_path,
    token,
    DEFAULT_MAX_LOG_SIZE,
    DEFAULT_MAX_LOG_BACKUPS,
  );
}

/// Copies the output of a child to `log_path` on a background thread with
/// configurable file size and backup generation bounds.
pub fn spawn_log_forwarder_bounded(
  reader: impl Read + Send + 'static,
  log_path: PathBuf,
  token: String,
  max_size: u64,
  max_backups: usize,
) {
  std::thread::spawn(move || {
    let Ok(mut writer) = RollingLogWriter::new(log_path, max_size, max_backups, token) else {
      return;
    };
    let mut reader = BufReader::new(reader);
    let limit = usize::try_from(max_size).unwrap_or(usize::MAX);
    let mut buffer = Vec::new();
    let mut oversized = false;
    loop {
      let chunk = match reader.fill_buf() {
        Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
        Ok([]) | Err(_) => break,
        Ok(chunk) => chunk,
      };
      let newline = chunk.iter().position(|byte| *byte == b'\n');
      let count = newline.map_or(chunk.len(), |index| index + 1);
      if !oversized && buffer.len().saturating_add(count) <= limit {
        buffer.extend_from_slice(&chunk[..count]);
      } else {
        oversized = true;
        buffer.clear();
      }
      reader.consume(count);
      if newline.is_some() {
        let line = if oversized {
          std::borrow::Cow::Borrowed("[TRUNCATED_LOG_LINE]")
        } else {
          String::from_utf8_lossy(&buffer)
        };
        let _ = writer.write_line(&line);
        buffer.clear();
        oversized = false;
      }
    }
    if oversized {
      let _ = writer.write_line("[TRUNCATED_LOG_LINE]");
    } else if !buffer.is_empty() {
      let _ = writer.write_line(&String::from_utf8_lossy(&buffer));
    }
  });
}

/// The daemon owns the writer. The log continues to rotate after a client exits.
static DAEMON_LOG: OnceLock<Mutex<RollingLogWriter>> = OnceLock::new();

/// Opens the daemon log after the daemon gets its lifetime lock.
///
/// # Errors
///
/// Fails if the daemon cannot open or rotate its log.
pub fn initialize_daemon_log(path: PathBuf) -> io::Result<()> {
  let writer = RollingLogWriter::new_with_defaults(path, String::new())?;
  let _ = DAEMON_LOG.set(Mutex::new(writer));
  Ok(())
}

/// Writes an internal event to the daemon log, when this process owns the daemon.
pub fn record_daemon_error(message: &str) {
  if let Some(writer) = DAEMON_LOG.get() {
    let _ = writer
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .write_line(message);
  }
}

/// Writes a daemon event to the log with rotation and to the foreground terminal.
pub fn log_daemon(message: &str) {
  record_daemon_error(message);
  eprintln!("{message}");
}

/// Adds `option` to the end of a `JAVA_TOOL_OPTIONS` value, in quotes.
pub fn append_java_tool_option(existing: Option<&str>, option: &str) -> String {
  let quoted = quote_java_tool_option(option);
  match existing.map(str::trim).filter(|value| !value.is_empty()) {
    Some(existing) => format!("{existing} {quoted}"),
    None => quoted,
  }
}

/// Puts an option in quotes for the `JAVA_TOOL_OPTIONS` parser of the JVM. The
/// parser joins quoted fragments, but it does not interpret backslash escapes.
fn quote_java_tool_option(option: &str) -> String {
  if !option
    .chars()
    .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\''))
  {
    return option.to_string();
  }
  // A literal double quote ends the fragment. Single quotes enclose the double
  // quote, and then the double-quoted fragment continues.
  format!("\"{}\"", option.replace('"', "\"'\"'\""))
}
