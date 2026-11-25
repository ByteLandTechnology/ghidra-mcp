// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The shared state of the daemon: one entry for each session, and the jobs.
//!
//! # Concurrency
//!
//! - [`McpState::lifecycle_lock`] (async) puts in-memory session lifecycle
//!   checks, transition claims, and snapshot writes in sequence. A task never
//!   keeps it across an await, an RPC, project preparation, or a process stop.
//! - Each [`SessionEntry`] tracks its active transition and process stop count.
//!   Waiters for the same MD5 wait on [`McpState::notify`] outside the lock.
//! - Plain mutexes protect the session map and the job map. A task keeps them
//!   only for short sections that do not block, and never across an await. For
//!   this reason, most methods here are synchronous.
//! - [`McpState::notify`] wakes all waiters after each change. Each waiter
//!   examines its condition again. For this reason, an unnecessary wake-up does no damage.

#[cfg(test)]
mod tests;

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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
    /// The saved record, after the first launch writes its snapshot.
    record: Option<SessionRecord>,
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
    /// Identifier of the active launch-preparation or close transition for this MD5.
    transition: Option<u64>,
    /// `true` when the active transition closes the session.
    closing: bool,
    /// Active process starts or detached process stops that use this MD5 project.
    teardowns: usize,
}

impl SessionEntry {
    /// Makes an entry with an optional record and no job, connection, request, or process.
    fn new(record: Option<SessionRecord>) -> Self {
        Self {
            record,
            launch_job: None,
            connection: None,
            request: None,
            process: None,
            request_lock: Arc::new(tokio::sync::Mutex::new(())),
            transition: None,
            closing: false,
            teardowns: 0,
        }
    }

    /// Returns `true` when an uncreated entry has no active transition or teardown.
    fn is_unused(&self) -> bool {
        self.record.is_none()
            && self.transition.is_none()
            && self.teardowns == 0
            && self.process.is_none()
            && self.connection.is_none()
    }
}

/// Owns an in-flight per-session transition outside [`McpState::lifecycle_lock`].
pub(crate) struct TransitionGuard {
    /// Shared daemon state that holds the session entry.
    state: Arc<McpState>,
    /// Target session MD5.
    md5: String,
    /// Monotonic identifier of this transition claim.
    id: u64,
    /// `true` until [`Self::finish`] or [`Drop`] releases the claim.
    active: bool,
}

impl TransitionGuard {
    /// Releases the transition claim and wakes waiters.
    pub(crate) fn finish(mut self) {
        self.active = false;
        self.state.end_transition(&self.md5, self.id);
    }
}

impl Drop for TransitionGuard {
    fn drop(&mut self) {
        if self.active {
            self.state.end_transition(&self.md5, self.id);
        }
    }
}

/// Blocks new project opens on one MD5 until an active spawn or reap finishes.
pub(crate) struct TeardownGuard {
    /// Shared daemon state that holds the session entry.
    state: Arc<McpState>,
    /// Target session MD5.
    md5: String,
}

impl Drop for TeardownGuard {
    fn drop(&mut self) {
        self.state.end_teardown(&self.md5);
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
    /// Puts the session lifecycle transitions in order: open, launch, ready, disconnect and close.
    pub lifecycle_lock: tokio::sync::Mutex<()>,
    /// Wakes the waiters after each change of a session, a job or a process.
    pub notify: Notify,
    /// Shows whether shutdown started. After that, the daemon refuses new launches and processes.
    shutting_down: AtomicBool,
    /// Assigns unique identifiers to per-session transition claims.
    next_transition_id: AtomicU64,
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
            next_transition_id: AtomicU64::new(1),
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
            .filter(|entry| entry.record.is_some())
            .ok_or_else(|| DomainError::missing_target(md5, format!("unknown session: {md5}")))?;
        Ok(f(entry))
    }

    // Session records.

    /// Returns a copy of each session record.
    pub fn sessions(&self) -> Vec<SessionRecord> {
        self.entries()
            .values()
            .filter_map(|entry| entry.record.clone())
            .collect()
    }

    /// Returns a copy of the record of a session, if the session exists.
    pub fn find_session(&self, md5: &str) -> Option<SessionRecord> {
        self.entries()
            .get(md5)
            .and_then(|entry| entry.record.clone())
    }

    /// Returns a copy of the record of a session.
    ///
    /// # Errors
    ///
    /// Fails for an unknown session.
    pub fn session(&self, md5: &str) -> Result<SessionRecord> {
        self.with_entry(md5, |entry| {
            entry.record.clone().expect("verified session record")
        })
    }

    /// Returns the session if `token` is still its bridge credential. A relaunch
    /// replaces the credential.
    pub fn session_with_token(&self, md5: &str, token: &str) -> Option<SessionRecord> {
        self.find_session(md5)
            .filter(|session| session.agent_token == token)
    }

    /// Finds the live session that has the bearer token `token` as its credential.
    pub fn session_for_token(&self, token: &str) -> Option<String> {
        self.entries().values().find_map(|entry| {
            let session = entry.record.as_ref()?;
            (entry.transition.is_none() && session.agent_token == token && session.status.is_live())
                .then(|| session.session_id.clone())
        })
    }

    /// Saves a new or a replacement record. The other state of the session does not change.
    ///
    /// # Errors
    ///
    /// Fails if the daemon cannot write the snapshot.
    pub fn put_session(&self, record: &SessionRecord) -> Result<()> {
        let md5 = record.session_id.clone();
        self.entries()
            .entry(md5)
            .and_modify(|entry| entry.record = Some(record.clone()))
            .or_insert_with(|| SessionEntry::new(Some(record.clone())));
        self.write_session(record)
    }

    /// Changes the record of a session and saves its snapshot.
    ///
    /// # Errors
    ///
    /// Fails for an unknown session, or if the daemon cannot write the snapshot.
    pub fn update_session(&self, md5: &str, mutate: impl FnOnce(&mut SessionRecord)) -> Result<()> {
        let record = self.with_entry(md5, |entry| {
            let record = entry.record.as_mut().expect("verified session record");
            mutate(record);
            record.clone()
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
        if !self.has_transition(md5) && self.owns_launch(md5, job_id) {
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
        self.with_entry(md5, |entry| {
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
                return Err(DomainError::RequestInFlight {
                    md5: md5.to_string(),
                }
                .into());
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

    // Per-session transitions and Ghidra processes.

    /// Returns `true` when `md5` has an active launch-preparation or close transition.
    pub(crate) fn has_transition(&self, md5: &str) -> bool {
        self.entries()
            .get(md5)
            .is_some_and(|entry| entry.transition.is_some())
    }

    /// Returns `true` when `md5` has an active close transition.
    pub(crate) fn is_closing(&self, md5: &str) -> bool {
        self.entries().get(md5).is_some_and(|entry| entry.closing)
    }

    /// Claims exclusive per-MD5 transition ownership outside [`Self::lifecycle_lock`].
    pub(crate) fn begin_transition(self: &Arc<Self>, md5: &str, closing: bool) -> TransitionGuard {
        let id = self.next_transition_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut entries = self.entries();
            let entry = entries
                .entry(md5.to_string())
                .or_insert_with(|| SessionEntry::new(None));
            debug_assert!(entry.transition.is_none());
            entry.transition = Some(id);
            entry.closing = closing;
        }
        self.notify.notify_waiters();
        TransitionGuard {
            state: self.clone(),
            md5: md5.to_string(),
            id,
            active: true,
        }
    }

    /// Releases transition `id` on `md5` and wakes same-MD5 waiters.
    fn end_transition(&self, md5: &str, id: u64) {
        {
            let mut entries = self.entries();
            if let Some(entry) = entries.get_mut(md5) {
                if entry.transition == Some(id) {
                    entry.transition = None;
                    entry.closing = false;
                }
                if entry.is_unused() {
                    entries.remove(md5);
                }
            }
        }
        self.notify.notify_waiters();
    }

    /// Tracks one active process spawn or teardown on `md5`.
    pub(crate) fn begin_teardown(self: &Arc<Self>, md5: &str) -> TeardownGuard {
        {
            let mut entries = self.entries();
            let entry = entries
                .entry(md5.to_string())
                .or_insert_with(|| SessionEntry::new(None));
            entry.teardowns += 1;
        }
        TeardownGuard {
            state: self.clone(),
            md5: md5.to_string(),
        }
    }

    /// Releases one teardown count on `md5` and wakes waiters.
    fn end_teardown(&self, md5: &str) {
        {
            let mut entries = self.entries();
            if let Some(entry) = entries.get_mut(md5) {
                entry.teardowns = entry.teardowns.saturating_sub(1);
                if entry.is_unused() {
                    entries.remove(md5);
                }
            }
        }
        self.notify.notify_waiters();
    }

    /// Detaches the child process of `md5` and tracks its teardown barrier.
    pub(crate) fn take_process(
        self: &Arc<Self>,
        md5: &str,
    ) -> Option<(ManagedChild, TeardownGuard)> {
        let child = {
            let mut entries = self.entries();
            let entry = entries.get_mut(md5)?;
            let child = entry.process.take()?;
            entry.teardowns += 1;
            child
        };
        Some((
            child,
            TeardownGuard {
                state: self.clone(),
                md5: md5.to_string(),
            },
        ))
    }

    /// Returns `true` when `md5` still has a live child or an active teardown.
    pub(crate) fn has_teardown(&self, md5: &str) -> bool {
        self.entries()
            .get(md5)
            .is_some_and(|entry| entry.teardowns > 0 || entry.process.is_some())
    }

    /// Waits outside [`Self::lifecycle_lock`] until `md5` has no active teardown.
    pub(crate) async fn wait_teardown(&self, md5: &str) -> Result<()> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_shutting_down() {
                return Err(DomainError::ShuttingDown.into());
            }
            if !self.has_teardown(md5) {
                return Ok(());
            }
            notified.await;
        }
    }

    /// Records a spawned child and releases its spawn barrier in one step.
    pub(crate) fn commit_spawned_process(
        &self,
        md5: &str,
        child: ManagedChild,
        spawn_guard: TeardownGuard,
    ) -> Result<(), (ManagedChild, TeardownGuard)> {
        {
            let mut entries = self.entries();
            let Some(entry) = entries.get_mut(md5) else {
                return Err((child, spawn_guard));
            };
            if self.is_shutting_down() || entry.record.is_none() || entry.process.is_some() {
                return Err((child, spawn_guard));
            }
            entry.process = Some(child);
            entry.teardowns = entry.teardowns.saturating_sub(1);
            std::mem::forget(spawn_guard);
        }
        self.notify.notify_waiters();
        Ok(())
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
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !self.entries().values().any(|entry| entry.teardowns > 0) {
                break;
            }
            notified.await;
        }
        for entry in self.entries().values_mut() {
            entry.connection = None;
            entry.request = None;
        }
        self.notify.notify_waiters();
    }

    /// Stops a detached session process and releases `guard` after the process tree stops.
    pub(crate) async fn reap_detached(
        &self,
        child: ManagedChild,
        guard: TeardownGuard,
        grace: Duration,
    ) {
        let terminate = self.config.timeouts.graceful_kill;
        let kill = self.config.timeouts.force_kill;
        let _ = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            child.reap_or_kill(grace, terminate, kill);
        })
        .await;
    }

    /// Stops a child process in steps (see [`ManagedChild::reap_or_kill`]), on a
    /// thread that can block.
    pub async fn reap(&self, child: ManagedChild, grace: Duration) {
        let terminate = self.config.timeouts.graceful_kill;
        let kill = self.config.timeouts.force_kill;
        let _ =
            tokio::task::spawn_blocking(move || child.reap_or_kill(grace, terminate, kill)).await;
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
        self.job_map()
            .get(job_id)
            .map(|entry| entry.record.clone())
            .ok_or_else(|| {
                DomainError::missing_target(job_id, format!("unknown job: {job_id}")).into()
            })
    }

    /// Returns a copy of each job that the daemon still keeps.
    pub fn jobs(&self) -> Vec<JobRecord> {
        let mut map = self.job_map();
        Self::prune_jobs(&mut map);
        map.values().map(|entry| entry.record.clone()).collect()
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
                    return Err(DomainError::Internal {
                        message: job
                            .error
                            .unwrap_or_else(|| format!("job {} failed", job.id)),
                    }
                    .into());
                }
                JobStatus::Running => {}
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                let md5 = self
                    .job(job_id)
                    .ok()
                    .and_then(|j| j.session_id)
                    .unwrap_or_else(|| job_id.to_string());
                return Err(DomainError::AgentTimeout {
                    md5,
                    timeout_seconds: Some(timeout.as_secs()),
                }
                .into());
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
        sessions.insert(record.session_id.clone(), SessionEntry::new(Some(record)));
    }
    Ok(sessions)
}

/// Makes isolated daemon state without Ghidra processes or shared environment changes.
#[cfg(test)]
pub(crate) fn test_state(root: &std::path::Path) -> Arc<McpState> {
    test_state_with(root, McpConfig::default(), String::new())
}

/// Makes isolated daemon state with custom configuration and bridge WebSocket URL.
#[cfg(test)]
pub(crate) fn test_state_with(
    root: &std::path::Path,
    config: McpConfig,
    bridge_ws_url: String,
) -> Arc<McpState> {
    Arc::new(McpState {
        paths: McpPaths {
            config_toml: root.join("config.toml"),
            projects_dir: root.join("projects"),
            runtime_dir: root.join("run"),
            tmp_dir: root.join("tmp"),
        },
        config,
        bridge_ws_url,
        lifecycle_lock: tokio::sync::Mutex::new(()),
        notify: Notify::new(),
        shutting_down: AtomicBool::new(false),
        next_transition_id: AtomicU64::new(1),
        sessions: Mutex::default(),
        jobs: Mutex::default(),
    })
}
