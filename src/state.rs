// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The shared state of the daemon: one entry for each session, and the jobs.
//!
//! # Concurrency
//!
//! - [`McpState::lifecycle_lock`] (async) puts the session lifecycle
//!   transitions in sequence: open, launch, bridge handshake, disconnect and
//!   close. A task can keep it across an await, for example while a process stops.
//! - Plain mutexes protect the session map and the job map. A task keeps them
//!   only for short sections that do not block, and never across an await. For
//!   this reason, most methods here are synchronous.
//! - [`McpState::notify`] wakes all waiters after each change. Each waiter
//!   examines its condition again. For this reason, an unnecessary wake-up does no damage.

use crate::config::McpConfig;
use crate::error::DomainError;
use crate::model::{JobRecord, JobStatus, RpcEnvelope, RpcError, SessionRecord};
use crate::paths::{atomic_write, McpPaths};
use crate::process::ManagedChild;
use anyhow::Result;
use axum::extract::ws::Message;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::Instant;
use uuid::Uuid;

/// A bridge WebSocket connection that the daemon accepted.
#[derive(Clone)]
pub struct ConnectionHandle {
  /// A different value for each connection. It identifies a new connection of
  /// a bridge that connected again.
  pub conn_id: String,
  /// Puts frames in the queue of the send task of the connection.
  pub sender: mpsc::UnboundedSender<Message>,
}

/// A bridge request that waits for its response.
struct PendingRequest {
  /// The JSON-RPC request ID.
  id: String,
  /// The connection that sent the request. Only this connection can answer.
  conn_id: String,
  /// Gives the response to the caller that waits.
  sender: oneshot::Sender<RpcEnvelope>,
}

/// All the data that the daemon keeps for one session.
struct SessionEntry {
  /// The saved record.
  record: SessionRecord,
  /// The launch or relaunch job that owns the session now.
  launch_job: Option<String>,
  /// The bridge connection, after its handshake.
  connection: Option<ConnectionHandle>,
  /// The open request. The bridge serves one request at a time.
  request: Option<PendingRequest>,
  /// The `analyzeHeadless` process.
  process: Option<ManagedChild>,
  /// Serializes bridge requests from concurrent callers.
  request_lock: Arc<tokio::sync::Mutex<()>>,
}

impl SessionEntry {
  /// Makes an entry with no job, no connection, no request and no process.
  fn new(record: SessionRecord) -> Self {
    Self {
      record,
      launch_job: None,
      connection: None,
      request: None,
      process: None,
      request_lock: Arc::new(tokio::sync::Mutex::new(())),
    }
  }
}

/// Maximum number of finished job records kept in memory.
const MAX_FINISHED_JOBS: usize = 100;
/// Time to live for finished jobs before eviction.
const FINISHED_JOB_TTL: Duration = Duration::from_hours(1);

/// A job record and its timestamps for bounded retention.
struct JobEntry {
  /// The public job status and result.
  record: JobRecord,
  /// The job completion time that controls record expiration.
  finished_at: Option<Instant>,
  /// The typed failure, retained for callers that wait for this job.
  failure: Option<DomainError>,
}

impl JobEntry {
  /// Makes a new entry without a completion timestamp.
  fn new(record: JobRecord) -> Self {
    Self {
      record,
      finished_at: None,
      failure: None,
    }
  }
}

/// The state that all request handlers, bridge connections and background tasks share.
pub struct McpState {
  /// The locations of the files.
  pub paths: McpPaths,
  /// The loaded `config.toml`.
  pub config: McpConfig,
  /// The WebSocket URL to which a bridge connects.
  pub bridge_ws_url: String,
  /// Puts the session lifecycle transitions in sequence: open, launch, ready, disconnect and close.
  pub lifecycle_lock: tokio::sync::Mutex<()>,
  /// Wakes the waiters after each change of a session, a job or a process.
  pub notify: Notify,
  /// Shows whether shutdown started. After that, the daemon refuses new launches and processes.
  shutting_down: AtomicBool,
  /// All known sessions, with the MD5 as key.
  sessions: Mutex<HashMap<String, SessionEntry>>,
  /// All jobs since the start of the daemon, with the job ID as key.
  jobs: Mutex<HashMap<String, JobEntry>>,
}

impl McpState {
  /// Makes the directory layout, loads the configuration and restores the
  /// runtime session snapshots.
  pub fn initialize(bridge_ws_url: String) -> Result<Arc<Self>> {
    let paths = McpPaths::new()?;
    paths.ensure_layout()?;
    let config = McpConfig::load_or_create(&paths)?;
    let sessions = load_sessions(&paths)?;
    Ok(Arc::new(Self {
      paths,
      config,
      bridge_ws_url,
      lifecycle_lock: tokio::sync::Mutex::new(()),
      notify: Notify::new(),
      shutting_down: AtomicBool::new(false),
      sessions: Mutex::new(sessions),
      jobs: Mutex::default(),
    }))
  }

  /// Returns `true` after the shutdown started.
  pub fn is_shutting_down(&self) -> bool {
    self.shutting_down.load(Ordering::SeqCst)
  }

  /// Starts the shutdown. After that, the daemon refuses new launches and new processes.
  pub fn begin_shutdown(&self) {
    self.shutting_down.store(true, Ordering::SeqCst);
    self.notify.notify_waiters();
  }

  /// Locks the session map. Do not keep the guard across an await.
  fn entries(&self) -> MutexGuard<'_, HashMap<String, SessionEntry>> {
    self.sessions.lock().expect("session state lock poisoned")
  }

  /// Runs `f` on the entry of a session. Fails for an unknown session.
  fn with_entry<T>(&self, md5: &str, f: impl FnOnce(&mut SessionEntry) -> T) -> Result<T> {
    let mut entries = self.entries();
    let entry = entries
      .get_mut(md5)
      .ok_or_else(|| DomainError::missing_target(md5, format!("unknown session: {md5}")))?;
    Ok(f(entry))
  }

  // Session records.

  /// Returns a copy of each session record.
  pub fn sessions(&self) -> Vec<SessionRecord> {
    self
      .entries()
      .values()
      .map(|entry| entry.record.clone())
      .collect()
  }

  /// Returns a copy of the record of a session, if the session exists.
  pub fn find_session(&self, md5: &str) -> Option<SessionRecord> {
    self.entries().get(md5).map(|entry| entry.record.clone())
  }

  /// Returns a copy of the record of a session.
  ///
  /// # Errors
  ///
  /// Fails for an unknown session.
  pub fn session(&self, md5: &str) -> Result<SessionRecord> {
    self.with_entry(md5, |entry| entry.record.clone())
  }

  /// Returns the session if `token` is still its bridge credential. A relaunch
  /// replaces the credential.
  pub fn session_with_token(&self, md5: &str, token: &str) -> Option<SessionRecord> {
    self
      .find_session(md5)
      .filter(|session| session.agent_token == token)
  }

  /// Finds the live session that has the bearer token `token` as its credential.
  pub fn session_for_token(&self, token: &str) -> Option<String> {
    self.entries().values().find_map(|entry| {
      let session = &entry.record;
      (session.agent_token == token && session.status.is_live()).then(|| session.session_id.clone())
    })
  }

  /// Saves a new or a replacement record. The other state of the session does not change.
  ///
  /// # Errors
  ///
  /// Fails if the daemon cannot write the snapshot.
  pub fn put_session(&self, record: &SessionRecord) -> Result<()> {
    let md5 = record.session_id.clone();
    self
      .entries()
      .entry(md5)
      .and_modify(|entry| entry.record = record.clone())
      .or_insert_with(|| SessionEntry::new(record.clone()));
    self.write_session(record)
  }

  /// Changes the record of a session and saves its snapshot.
  ///
  /// # Errors
  ///
  /// Fails for an unknown session, or if the daemon cannot write the snapshot.
  pub fn update_session(&self, md5: &str, mutate: impl FnOnce(&mut SessionRecord)) -> Result<()> {
    let record = self.with_entry(md5, |entry| {
      mutate(&mut entry.record);
      entry.record.clone()
    })?;
    self.write_session(&record)
  }

  /// Saves the snapshot of a record and wakes the waiters.
  fn write_session(&self, session: &SessionRecord) -> Result<()> {
    atomic_write(
      &self.paths.session_json(&session.session_id),
      &serde_json::to_vec_pretty(session)?,
    )?;
    self.notify.notify_waiters();
    Ok(())
  }

  // Launch jobs.

  /// Returns the job that owns the current launch of a session.
  pub fn launch_job(&self, md5: &str) -> Option<String> {
    self.entries().get(md5)?.launch_job.clone()
  }

  /// Returns `true` if `job_id` still owns the launch of the session. A newer
  /// launch replaces the job, and a close removes it.
  pub fn owns_launch(&self, md5: &str, job_id: &str) -> bool {
    self.launch_job(md5).as_deref() == Some(job_id)
  }

  /// Sets or removes the job that owns the launch of a session.
  pub fn set_launch_job(&self, md5: &str, job_id: Option<String>) {
    if let Some(entry) = self.entries().get_mut(md5) {
      entry.launch_job = job_id;
    }
    self.notify.notify_waiters();
  }

  /// Fails a launch job. If the job still owns the session, the session also fails.
  pub async fn fail_launch(&self, md5: &str, job_id: &str, error: DomainError) {
    let _guard = self.lifecycle_lock.lock().await;
    let message = error.to_string();
    self.fail_job_error(job_id, error);
    if self.owns_launch(md5, job_id) {
      let _ = self.update_session(md5, |session| session.mark_error(&message));
      self.set_launch_job(md5, None);
    }
  }

  // Bridge connection and requests.

  /// Returns the bridge connection of the session.
  pub fn connection(&self, md5: &str) -> Option<ConnectionHandle> {
    self.entries().get(md5)?.connection.clone()
  }

  /// Attaches a connection if the session does not have one.
  pub fn attach_bridge(&self, md5: &str, handle: ConnectionHandle) -> bool {
    self
      .with_entry(md5, |entry| {
        if entry.connection.is_some() {
          return false;
        }
        entry.connection = Some(handle);
        true
      })
      .unwrap_or(false)
  }

  /// Removes the connection of the session. Its open request gets a `BRIDGE_DISCONNECTED` error.
  pub fn detach_bridge(&self, md5: &str, reason: &str) {
    let _ = self.with_entry(md5, |entry| {
      entry.connection = None;
      if let Some(request) = entry.request.take() {
        let mut envelope = RpcEnvelope::response(request.id, md5.to_string(), 502);
        envelope.error = Some(RpcError {
          code: "BRIDGE_DISCONNECTED".to_string(),
          message: reason.to_string(),
          target: Some(md5.to_string()),
        });
        let _ = request.sender.send(envelope);
      }
    });
    self.notify.notify_waiters();
  }

  /// Removes the bridge only if `conn_id` is still the connection of the session.
  pub fn detach_bridge_if_current(&self, md5: &str, conn_id: &str, reason: &str) -> bool {
    let current = self
      .connection(md5)
      .is_some_and(|handle| handle.conn_id == conn_id);
    if current {
      self.detach_bridge(md5, reason);
    }
    current
  }

  /// Returns the per-session request serialization lock.
  ///
  /// # Errors
  ///
  /// Fails for an unknown session.
  pub fn request_lock(&self, md5: &str) -> Result<Arc<tokio::sync::Mutex<()>>> {
    self.with_entry(md5, |entry| entry.request_lock.clone())
  }

  /// Records a request and returns the connection for the request.
  ///
  /// # Errors
  ///
  /// Fails for an unknown session, for a session without a bridge, and for a
  /// session that has an open request.
  pub fn begin_request(
    &self,
    md5: &str,
    request_id: &str,
    sender: oneshot::Sender<RpcEnvelope>,
  ) -> Result<ConnectionHandle> {
    self.with_entry(md5, |entry| {
      let Some(connection) = entry.connection.clone() else {
        return Err(DomainError::disconnected(md5).into());
      };
      if entry.request.is_some() {
        return Err(
          DomainError::RequestInFlight {
            md5: md5.to_string(),
          }
          .into(),
        );
      }
      entry.request = Some(PendingRequest {
        id: request_id.to_string(),
        conn_id: connection.conn_id.clone(),
        sender,
      });
      Ok(connection)
    })?
  }

  /// Removes a request that timed out or that the daemon did not send. Then the
  /// session accepts the next request.
  pub fn abandon_request(&self, md5: &str, request_id: &str) {
    let _ = self.with_entry(md5, |entry| {
      if entry
        .request
        .as_ref()
        .is_some_and(|request| request.id == request_id)
      {
        entry.request = None;
      }
    });
  }

  /// Gives a bridge response to its caller, if it answers the request that `conn_id` sent.
  pub fn deliver_response(
    &self,
    md5: &str,
    conn_id: &str,
    request_id: &str,
    envelope: RpcEnvelope,
  ) {
    let request = self.with_entry(md5, |entry| {
      entry
        .request
        .take_if(|request| request.id == request_id && request.conn_id == conn_id)
    });
    if let Ok(Some(request)) = request {
      let _ = request.sender.send(envelope);
    }
  }

  /// Gives a bridge protocol error without a request ID to the open request that `conn_id` sent.
  pub fn deliver_protocol_error(&self, md5: &str, conn_id: &str, mut envelope: RpcEnvelope) {
    let request = self.with_entry(md5, |entry| {
      entry.request.take_if(|request| request.conn_id == conn_id)
    });
    if let Ok(Some(request)) = request {
      envelope.id = Some(request.id);
      let _ = request.sender.send(envelope);
    }
  }

  // Ghidra processes.

  /// Records a child process. Returns the child if the shutdown started or the session is gone.
  pub fn register_process(&self, md5: &str, child: ManagedChild) -> Result<(), ManagedChild> {
    let mut entries = self.entries();
    match entries.get_mut(md5) {
      Some(entry) if !self.is_shutting_down() => {
        entry.process = Some(child);
        Ok(())
      }
      _ => Err(child),
    }
  }

  /// Returns the exit status if the process of the session stopped. Then the
  /// daemon forgets the process.
  ///
  /// # Errors
  ///
  /// Fails for an unknown session, or if the daemon cannot read the status.
  pub fn poll_process_exit(&self, md5: &str) -> Result<Option<ExitStatus>> {
    self.with_entry(md5, |entry| {
      let Some(child) = &mut entry.process else {
        return Ok(None);
      };
      let status = child.try_wait()?;
      if status.is_some() {
        entry.process = None;
      }
      Ok(status)
    })?
  }

  /// Stops the Ghidra process of a session. First, the process has `grace` to stop by itself.
  pub async fn stop_process(&self, md5: &str, grace: Duration) {
    let child = self
      .entries()
      .get_mut(md5)
      .and_then(|entry| entry.process.take());
    if let Some(child) = child {
      self.reap(child, grace).await;
    }
  }

  /// Stops all processes and removes all bridges, for the shutdown of the daemon.
  pub async fn stop_all(&self) {
    let children: Vec<ManagedChild> = self
      .entries()
      .values_mut()
      .filter_map(|entry| entry.process.take())
      .collect();
    futures::future::join_all(
      children
        .into_iter()
        .map(|child| self.reap(child, Duration::from_secs(30))),
    )
    .await;
    for entry in self.entries().values_mut() {
      entry.connection = None;
      entry.request = None;
    }
    self.notify.notify_waiters();
  }

  /// Stops a child process in steps (see [`ManagedChild::reap_or_kill`]), on a
  /// thread that can block.
  pub async fn reap(&self, child: ManagedChild, grace: Duration) {
    let terminate = self.config.timeouts.graceful_kill;
    let kill = self.config.timeouts.force_kill;
    let _ = tokio::task::spawn_blocking(move || child.reap_or_kill(grace, terminate, kill)).await;
  }

  // Jobs.

  /// Locks the job map. Do not keep the guard across an await.
  fn job_map(&self) -> MutexGuard<'_, HashMap<String, JobEntry>> {
    self.jobs.lock().expect("job state lock poisoned")
  }

  /// Removes old finished jobs above the TTL or capacity limit.
  fn prune_jobs(jobs: &mut HashMap<String, JobEntry>) {
    let now = Instant::now();
    jobs.retain(|_, entry| match entry.finished_at {
      Some(finished) => now.duration_since(finished) < FINISHED_JOB_TTL,
      None => true,
    });
    let finished_count = jobs.values().filter(|e| e.finished_at.is_some()).count();
    if finished_count > MAX_FINISHED_JOBS {
      let excess = finished_count - MAX_FINISHED_JOBS;
      let mut finished_entries: Vec<(String, Instant)> = jobs
        .iter()
        .filter_map(|(id, e)| e.finished_at.map(|t| (id.clone(), t)))
        .collect();
      finished_entries.sort_by_key(|(_, t)| *t);
      for (id, _) in finished_entries.into_iter().take(excess) {
        jobs.remove(&id);
      }
    }
  }

  /// Makes a job that runs.
  pub fn insert_job(&self, kind: &'static str, md5: Option<String>) -> JobRecord {
    let job = JobRecord {
      id: Uuid::new_v4().to_string(),
      kind,
      status: JobStatus::Running,
      session_id: md5,
      progress: None,
      result: None,
      error: None,
    };
    let mut map = self.job_map();
    Self::prune_jobs(&mut map);
    map.insert(job.id.clone(), JobEntry::new(job.clone()));
    self.notify.notify_waiters();
    job
  }

  /// Returns a copy of a job.
  ///
  /// # Errors
  ///
  /// Fails for an unknown job.
  pub fn job(&self, job_id: &str) -> Result<JobRecord> {
    self
      .job_map()
      .get(job_id)
      .map(|entry| entry.record.clone())
      .ok_or_else(|| DomainError::missing_target(job_id, format!("unknown job: {job_id}")).into())
  }

  /// Changes a job and wakes the waiters.
  fn update_job(&self, job_id: &str, mutate: impl FnOnce(&mut JobRecord)) {
    if let Some(entry) = self.job_map().get_mut(job_id) {
      mutate(&mut entry.record);
    }
    self.notify.notify_waiters();
  }

  /// Completes or fails a job that runs. The daemon does not change a job after it ends.
  pub fn finish_job(&self, job_id: &str, outcome: Result<Value, DomainError>) {
    let mut map = self.job_map();
    if let Some(entry) = map.get_mut(job_id) {
      if entry.record.status == JobStatus::Running {
        match outcome {
          Ok(result) => {
            entry.record.status = JobStatus::Completed;
            entry.record.result = Some(result);
            entry.record.error = None;
          }
          Err(error) => {
            entry.record.status = JobStatus::Failed;
            entry.record.error = Some(error.to_string());
            entry.failure = Some(error);
          }
        }
        entry.finished_at = Some(Instant::now());
      }
    }
    Self::prune_jobs(&mut map);
    self.notify.notify_waiters();
  }

  /// Fails a job that runs with an explicit domain error.
  pub fn fail_job_error(&self, job_id: &str, error: DomainError) {
    self.finish_job(job_id, Err(error));
  }

  /// Records the latest progress of an analysis job. If there is an error, it
  /// also records the error.
  pub fn set_job_progress(&self, job_id: &str, progress: Option<Value>, error: Option<String>) {
    self.update_job(job_id, |job| {
      job.progress = progress;
      if error.is_some() {
        job.error = error;
      }
    });
  }

  /// Returns the current record of a job. If `wait` has a value, it first waits
  /// for the job to finish, for a maximum of `wait`.
  ///
  /// # Errors
  ///
  /// Fails for an unknown job. During a wait, it also fails if the job failed
  /// or the time expired.
  pub async fn await_job(&self, job_id: &str, wait: Option<Duration>) -> Result<JobRecord> {
    let Some(timeout) = wait else {
      return self.job(job_id);
    };
    let deadline = Instant::now() + timeout;
    loop {
      let notified = self.notify.notified();
      tokio::pin!(notified);
      notified.as_mut().enable();
      let job = self.job(job_id)?;
      match job.status {
        JobStatus::Completed => return Ok(job),
        JobStatus::Failed => {
          if let Some(error) = self
            .job_map()
            .get(job_id)
            .and_then(|entry| entry.failure.clone())
          {
            return Err(error.into());
          }
          return Err(
            DomainError::Internal {
              message: job
                .error
                .unwrap_or_else(|| format!("job {} failed", job.id)),
            }
            .into(),
          );
        }
        JobStatus::Running => {}
      }
      if tokio::time::timeout_at(deadline, notified).await.is_err() {
        let md5 = self
          .job(job_id)
          .ok()
          .and_then(|j| j.session_id)
          .unwrap_or_else(|| job_id.to_string());
        return Err(
          DomainError::AgentTimeout {
            md5,
            timeout_seconds: Some(timeout.as_secs()),
          }
          .into(),
        );
      }
    }
  }
}

/// Loads the runtime snapshots. After a restart, no bridge has a connection.
/// Thus, live sessions become stale, and their old credentials become invalid.
fn load_sessions(paths: &McpPaths) -> Result<HashMap<String, SessionEntry>> {
  let mut sessions = HashMap::new();
  let Ok(dirs) = fs::read_dir(paths.sessions_dir()) else {
    return Ok(sessions);
  };
  for dir in dirs {
    let path = paths.session_json(&dir?.file_name().to_string_lossy());
    if !path.is_file() {
      continue;
    }
    let Some(mut record) = fs::read(&path)
      .ok()
      .and_then(|bytes| serde_json::from_slice::<SessionRecord>(&bytes).ok())
    else {
      crate::process::log_daemon(&format!(
        "ignoring invalid runtime session snapshot: {}",
        path.display()
      ));
      continue;
    };
    record.mark_restored();
    atomic_write(&path, &serde_json::to_vec_pretty(&record)?)?;
    sessions.insert(record.session_id.clone(), SessionEntry::new(record));
  }
  Ok(sessions)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bridge::{agent_ws, AGENT_WS_PATH};
  use crate::model::SessionStatus;
  use axum::{routing::get, Router};
  use serde_json::json;
  use std::net::SocketAddr;
  use std::path::Path;
  use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
  use tokio::net::{TcpListener, TcpStream};

  /// Creates isolated daemon state without Ghidra processes or shared environment changes.
  fn test_state(root: &Path) -> Arc<McpState> {
    Arc::new(McpState {
      paths: McpPaths {
        config_toml: root.join("config.toml"),
        projects_dir: root.join("projects"),
        runtime_dir: root.join("run"),
        tmp_dir: root.join("tmp"),
      },
      config: McpConfig::default(),
      bridge_ws_url: String::new(),
      lifecycle_lock: tokio::sync::Mutex::new(()),
      notify: Notify::new(),
      shutting_down: AtomicBool::new(false),
      sessions: Mutex::default(),
      jobs: Mutex::default(),
    })
  }

  /// Opens an authenticated WebSocket through the bridge endpoint.
  async fn connect_bridge(address: SocketAddr, token: &str) -> TcpStream {
    let mut socket = TcpStream::connect(address).await.unwrap();
    let request = format!(
      "GET {AGENT_WS_PATH} HTTP/1.1\r\nHost: {address}\r\n\
       Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
       Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 101 "), "{line}");
    loop {
      line.clear();
      assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
      if line == "\r\n" {
        break;
      }
    }
    reader.into_inner()
  }

  /// Sends a masked WebSocket text frame through the test connection.
  async fn send_text(socket: &mut TcpStream, text: &str) {
    let length = u16::try_from(text.len()).unwrap();
    let mask: [u8; 4] = Uuid::new_v4().as_bytes()[..4].try_into().unwrap();
    let mut frame = vec![0x81];
    if length < 126 {
      frame.push(0x80 | u8::try_from(length).unwrap());
    } else {
      frame.push(0xfe);
      frame.extend_from_slice(&length.to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    frame.extend(
      text
        .bytes()
        .enumerate()
        .map(|(index, byte)| byte ^ mask[index % 4]),
    );
    socket.write_all(&frame).await.unwrap();
  }

  /// Checks request failure, session state, and socket closure after an invalid bridge message.
  #[tokio::test]
  async fn disconnects_bridge_after_invalid_messages() {
    let root = tempfile::tempdir().unwrap();
    let state = test_state(root.path());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new()
      .route(AGENT_WS_PATH, get(agent_ws))
      .with_state(state.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let md5 = "0123456789abcdef0123456789abcdef";

    for invalid in [
      "not JSON",
      r#"{"jsonrpc":"1.0","id":"request","result":{}}"#,
      r#"{"jsonrpc":"2.0","id":"request","result":{},"extra":true}"#,
      r#"{"jsonrpc":"2.0","id":"request","result":{},"error":{"code":-32603,"message":"error"}}"#,
    ] {
      tokio::time::timeout(Duration::from_secs(2), async {
        let token = Uuid::new_v4().to_string();
        state
          .put_session(&SessionRecord::launching(
            md5.into(),
            "binary".into(),
            token.clone(),
          ))
          .unwrap();
        let mut socket = connect_bridge(address, &token).await;
        send_text(
          &mut socket,
          &json!({
            "jsonrpc": "2.0", "method": "ghidra.ready",
            "params": { "session_id": md5, "program_name": "binary" }
          })
          .to_string(),
        )
        .await;
        loop {
          let notified = state.notify.notified();
          tokio::pin!(notified);
          notified.as_mut().enable();
          if state.session(md5).unwrap().status == SessionStatus::Ready {
            break;
          }
          notified.await;
        }

        let (sender, receiver) = oneshot::channel();
        state.begin_request(md5, "valid", sender).unwrap();
        send_text(
          &mut socket,
          r#"{"jsonrpc":"2.0","id":"valid","result":{"ok":true}}"#,
        )
        .await;
        assert_eq!(receiver.await.unwrap().result, Some(json!({ "ok": true })));

        let (sender, receiver) = oneshot::channel();
        state.begin_request(md5, "request", sender).unwrap();
        send_text(&mut socket, invalid).await;
        let response = receiver.await.unwrap();
        assert_eq!(response.id.as_deref(), Some("request"));
        assert_eq!(response.status, Some(502));
        assert_eq!(response.error.unwrap().code, "BRIDGE_DISCONNECTED");
        assert_eq!(socket.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(state.connection(md5).is_none());
        let session = state.session(md5).unwrap();
        assert_eq!(session.status, SessionStatus::Disconnected);
        assert!(!session.ws_connected);
      })
      .await
      .unwrap_or_else(|_| panic!("bridge did not disconnect after: {invalid}"));
    }
    server.abort();
    let _ = server.await;
  }
}
