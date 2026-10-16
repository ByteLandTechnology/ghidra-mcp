// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Records that the daemon shares between its modules: sessions and their
//! state machine, jobs, and bridge responses.
//!
//! These types are also wire formats. [`SessionRecord`] is the runtime
//! snapshot `session.json`. The daemon returns [`SessionRecord::summary`],
//! [`JobRecord`] and [`RpcEnvelope`] to MCP clients. For this reason, the
//! field names and the value spellings are part of the public contract.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;

/// The lifecycle status of a session.
///
/// ```text
/// Launching ──► Starting ──► Ready ◄──► Disconnected
///     │            │           │              │
///     ▼            ▼           ▼              ▼ (daemon restart)
///   Error        Error   Closed / Killed    Stale
/// ```
///
/// The next use of a `Disconnected` or `Stale` session relaunches it.
/// `Closed`, `Killed` and `Error` are final, until a client opens the binary again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
  /// The daemon made the record. It did not start `analyzeHeadless` yet.
  Launching,
  /// The process runs. The daemon waits for the `ghidra.ready` handshake of the bridge.
  Starting,
  /// The bridge has a connection and serves requests.
  Ready,
  /// The bridge disconnected. The next use of the session relaunches it.
  Disconnected,
  /// The daemon restored the session from a snapshot after a restart. The next use relaunches it.
  Stale,
  /// A client closed the session. The bridge saved the program and stopped.
  Closed,
  /// A client closed the session. The daemon killed the process.
  Killed,
  /// The launch failed. `last_error` gives the reason.
  Error,
}

impl SessionStatus {
  /// Returns `true` if the next use of the session relaunches it.
  pub fn is_recoverable(self) -> bool {
    matches!(self, Self::Stale | Self::Disconnected)
  }

  /// Returns `true` if a launch is in progress.
  pub fn is_launching(self) -> bool {
    matches!(self, Self::Launching | Self::Starting)
  }

  /// Returns `true` if the process of the session can still run.
  pub fn is_live(self) -> bool {
    matches!(
      self,
      Self::Launching | Self::Starting | Self::Ready | Self::Disconnected
    )
  }

  /// Returns `true` if only a new `session.open` can start the session again.
  pub fn is_terminal(self) -> bool {
    matches!(self, Self::Closed | Self::Killed | Self::Error)
  }
}

impl fmt::Display for SessionStatus {
  /// Writes the lowercase name that the wire format uses.
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.serialize(f)
  }
}

/// The runtime state of one session. The daemon saves it as `session.json`
/// in the runtime directory. The record does not depend on the project on disk.
/// If you delete the runtime directory, you lose only this record, not the analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
  /// The lowercase MD5 of the binary. It identifies the session.
  pub session_id: String,
  /// The original file name of the binary, for display.
  pub file_name: String,
  /// The bridge credential of the current launch. The daemon never writes it to
  /// disk. For this reason, the daemon must relaunch a restored session before
  /// a bridge can connect.
  #[serde(skip_serializing, default)]
  pub agent_token: String,
  /// The position of the session in its lifecycle.
  pub status: SessionStatus,
  /// `true` if a bridge connection exists.
  pub ws_connected: bool,
  /// The reason for the last failure or disconnection.
  pub last_error: Option<String>,
}

/// State transitions. Each status change uses one of these methods. For this
/// reason, the rules for each transition are in one location.
impl SessionRecord {
  /// Makes a record for a new launch. `agent_token` is the credential of the launch.
  pub fn launching(md5: String, file_name: String, agent_token: String) -> Self {
    Self {
      session_id: md5,
      file_name,
      agent_token,
      status: SessionStatus::Launching,
      ws_connected: false,
      last_error: None,
    }
  }

  /// Records that `analyzeHeadless` started.
  pub fn mark_starting(&mut self) {
    self.status = SessionStatus::Starting;
    self.last_error = None;
  }

  /// Records that the bridge completed its handshake.
  pub fn mark_ready(&mut self) {
    self.status = SessionStatus::Ready;
    self.ws_connected = true;
    self.last_error = None;
  }

  /// Records that the bridge connection closed. A closed or killed session does not change.
  pub fn mark_disconnected(&mut self) {
    self.ws_connected = false;
    if !matches!(self.status, SessionStatus::Closed | SessionStatus::Killed) {
      self.status = SessionStatus::Disconnected;
      self.last_error = Some("bridge disconnected".to_string());
    }
  }

  /// Records that the launch failed with `message`.
  pub fn mark_error(&mut self, message: &str) {
    self.status = SessionStatus::Error;
    self.ws_connected = false;
    self.last_error = Some(message.to_string());
  }

  /// Records that a client closed the session. If `force` is `true`, the daemon
  /// killed the process. The credential becomes invalid. Then the old bridge cannot connect again.
  pub fn mark_closed(&mut self, force: bool) {
    self.status = if force {
      SessionStatus::Killed
    } else {
      SessionStatus::Closed
    };
    self.ws_connected = false;
    self.agent_token.clear();
  }

  /// Prepares a record that the daemon loaded after a restart. No bridge is
  /// connected. For this reason, a live session becomes stale.
  pub fn mark_restored(&mut self) {
    self.agent_token.clear();
    self.ws_connected = false;
    if self.status.is_live() {
      self.status = SessionStatus::Stale;
      self
        .last_error
        .get_or_insert_with(|| "persisted session recovered without an active bridge".to_string());
    }
  }

  /// Returns the public summary. It contains no paths, no errors and no credentials.
  pub fn summary(&self) -> Value {
    json!({
        "md5": self.session_id,
        "fileName": self.file_name,
        "status": self.status,
        "connected": self.ws_connected
    })
  }
}

/// The status of a background job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
  /// The job runs.
  Running,
  /// The job completed. `result` contains the result.
  Completed,
  /// The job failed. `error` contains the reason.
  Failed,
}

/// A background job. `job.get` reads it, and `job.wait` waits for it.
/// The daemon keeps jobs only in memory. When the daemon stops, the jobs are lost.
#[derive(Debug, Clone, Serialize)]
pub struct JobRecord {
  /// The random job ID.
  pub id: String,
  /// One of the [`job_kind`] values.
  pub kind: &'static str,
  /// The status of the job.
  pub status: JobStatus,
  /// The session of the job.
  #[serde(rename = "md5")]
  pub session_id: Option<String>,
  /// The latest progress report of an analysis job.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub progress: Option<Value>,
  /// The result of a completed job.
  pub result: Option<Value>,
  /// The reason for the failure, or the latest error that an analysis reported.
  pub error: Option<String>,
}

/// The values of [`JobRecord::kind`].
pub mod job_kind {
  /// The import of a new binary and the launch of its first session.
  pub const ANALYZE_BINARY: &str = "analyze-binary";
  /// The relaunch of the bridge of a known session.
  pub const RECOVER_SESSION_BRIDGE: &str = "recover-session-bridge";
  /// A Ghidra auto-analysis.
  pub const START_ANALYSIS: &str = "start-analysis";
}

/// A bridge response. The daemon returns it to MCP clients as `{"response": ...}`.
///
/// It uses the shape of an earlier internal envelope of the daemon. For this
/// reason, `v` and `type` are constant.
#[derive(Debug, Clone, Serialize)]
pub struct RpcEnvelope {
  /// The envelope version. It is always `1`.
  pub v: i32,
  /// Always `"response"`.
  pub r#type: &'static str,
  /// The request ID.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub id: Option<String>,
  /// The session that answered.
  #[serde(rename = "md5", skip_serializing_if = "Option::is_none")]
  pub session_id: Option<String>,
  /// An HTTP-style status: 200 for a success, or else the error status of the bridge.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub status: Option<i32>,
  /// The result of the method, for a success.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub result: Option<Value>,
  /// The error, for a failure.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<RpcError>,
  /// The raw `error.data` of the bridge, with the structured details.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error_data: Option<Value>,
}

impl RpcEnvelope {
  /// Makes an envelope for request `id` of `session_id`, without a result or an error.
  pub fn response(id: String, session_id: String, status: i32) -> Self {
    Self {
      v: 1,
      r#type: "response",
      id: Some(id),
      session_id: Some(session_id),
      status: Some(status),
      result: None,
      error: None,
      error_data: None,
    }
  }
}

/// A bridge error.
#[derive(Debug, Clone, Serialize)]
pub struct RpcError {
  /// A machine-readable code, for example `not_found` or `BRIDGE_DISCONNECTED`.
  pub code: String,
  /// A description for a person.
  pub message: String,
  /// The argument or the object of the error, for example `/selector`.
  pub target: Option<String>,
}
