// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The user configuration: `config.toml` in the persistent home.
//!
//! When the daemon starts for the first time, it writes [`DEFAULT_CONFIG`] to the file. All
//! keys are optional. The daemon ignores unknown sections and keys. For this
//! reason, the daemon can load older and newer files. It refuses only
//! syntax errors and removed settings.
//!
//! ```toml
//! [ghidra]
//! home = "/opt/ghidra"            # or GHIDRA_INSTALL_DIR / GHIDRA_HOME
//! analyze_headless = ""           # an analyzeHeadless path
//!
//! [analysis]
//! max_cpu = 4
//!
//! [timeouts]
//! process_spawn_timeout_sec = 30
//! analysis_import_timeout_sec = 1800
//! bridge_connect_timeout_sec = 30
//! agent_ready_timeout_sec = 30
//! bridge_disconnect_grace_sec = 5
//! graceful_kill_timeout_sec = 10
//! force_kill_timeout_sec = 5
//! rpc_ms = 30000
//! daemon_start_timeout_sec = 8
//! ipc_handshake_timeout_sec = 5
//! ```

use crate::paths::McpPaths;
use anyhow::{bail, Context, Result};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_with::{serde_as, DurationMilliSeconds, DurationSeconds, NoneAsEmptyString};
use std::fs;
use std::io::Write;
use std::time::Duration;

/// The file that the daemon writes at the first start. All other keys have their default values.
const DEFAULT_CONFIG: &str = r"# ghidra-mcp config

[ghidra]

[analysis]
max_cpu = 4
";

/// The loaded configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct McpConfig {
  /// `[ghidra]`: the location of Ghidra.
  pub ghidra: GhidraConfig,
  /// `[analysis]`: the resource limits for Ghidra.
  pub analysis: AnalysisConfig,
  /// `[timeouts]`: the time limits for launches, requests and the shutdown.
  pub timeouts: Timeouts,
}

/// The `[ghidra]` section.
#[serde_as]
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct GhidraConfig {
  /// The Ghidra installation directory. An empty string has the same effect as no value.
  #[serde_as(as = "NoneAsEmptyString")]
  pub home: Option<String>,
  /// The path of `analyzeHeadless`. An empty string has the same effect as no value.
  #[serde_as(as = "NoneAsEmptyString")]
  pub analyze_headless: Option<String>,
  /// Removed: the Java temporary directory is always the runtime `tmp/`.
  java_tmp_dir: Option<IgnoredAny>,
  /// Removed: the executable contains the bridge script.
  script_path: Option<IgnoredAny>,
  /// Removed: the executable contains the bridge script.
  bridge_script: Option<IgnoredAny>,
}

/// The `[analysis]` section.
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct AnalysisConfig {
  /// The value for `analyzeHeadless -max-cpu`.
  pub max_cpu: u32,
}

impl Default for AnalysisConfig {
  fn default() -> Self {
    Self { max_cpu: 4 }
  }
}

/// The `[timeouts]` section. The keys end in `_sec`, but `rpc_ms` is in milliseconds.
#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Timeouts {
  /// The time to start the `analyzeHeadless` process.
  #[serde(rename = "process_spawn_timeout_sec")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub process_spawn: Duration,
  /// The time to import a binary into a new project. It is also the default wait for an analysis.
  #[serde(rename = "analysis_import_timeout_sec")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub analysis_import: Duration,
  /// A part of the total launch time. See [`McpConfig::launch_timeout`].
  #[serde(rename = "bridge_connect_timeout_sec")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub bridge_connect: Duration,
  /// The time for a new bridge connection to send `ghidra.ready`.
  #[serde(rename = "agent_ready_timeout_sec")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub agent_ready: Duration,
  /// The time for a process to stop by itself after its bridge disconnects or
  /// its session closes. After this time, the daemon terminates the process.
  #[serde(rename = "bridge_disconnect_grace_sec")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub bridge_disconnect_grace: Duration,
  /// The time for a process to stop after the daemon tells it to terminate.
  #[serde(rename = "graceful_kill_timeout_sec")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub graceful_kill: Duration,
  /// The time for a process to stop after the daemon kills it.
  #[serde(rename = "force_kill_timeout_sec")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub force_kill: Duration,
  /// The time for one bridge request.
  #[serde(rename = "rpc_ms")]
  #[serde_as(as = "DurationMilliSeconds<u64>")]
  pub rpc: Duration,
  /// The time to wait for a daemon process in proxy mode.
  #[serde(rename = "daemon_start_timeout_sec", default = "default_daemon_start")]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub daemon_start: Duration,
  /// The timeout for the IPC handshake between proxy and daemon.
  #[serde(
    rename = "ipc_handshake_timeout_sec",
    default = "default_ipc_handshake"
  )]
  #[serde_as(as = "DurationSeconds<u64>")]
  pub ipc_handshake: Duration,
}

/// The default daemon start timeout, in seconds.
const fn default_daemon_start() -> Duration {
  Duration::from_secs(8)
}

/// The default IPC handshake timeout, in seconds.
const fn default_ipc_handshake() -> Duration {
  Duration::from_secs(5)
}

impl Default for Timeouts {
  fn default() -> Self {
    Self {
      process_spawn: Duration::from_secs(30),
      analysis_import: Duration::from_mins(30),
      bridge_connect: Duration::from_secs(30),
      agent_ready: Duration::from_secs(30),
      bridge_disconnect_grace: Duration::from_secs(5),
      graceful_kill: Duration::from_secs(10),
      force_kill: Duration::from_secs(5),
      rpc: Duration::from_secs(30),
      daemon_start: Duration::from_secs(8),
      ipc_handshake: Duration::from_secs(5),
    }
  }
}

impl McpConfig {
  /// Loads `config.toml`. If the file does not exist, it first writes [`DEFAULT_CONFIG`] to it.
  ///
  /// # Errors
  ///
  /// Fails in these conditions:
  ///
  /// - The daemon cannot write or read the file.
  /// - The file is not valid TOML, or a value has the wrong type.
  /// - The file sets a removed key.
  pub fn load_or_create(paths: &McpPaths) -> Result<Self> {
    let path = &paths.config_toml;
    let parent = path.parent().context("configuration path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(DEFAULT_CONFIG.as_bytes())?;
    file.as_file().sync_all()?;
    // Concurrent clients see a complete file. Never replace a user's configuration.
    // If another client made the file first, this client keeps that file. The
    // Rust removes the temporary file.
    match file.persist_noclobber(path) {
      Ok(_) => {}
      Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {}
      Err(error) => return Err(error).with_context(|| format!("creating {}", path.display())),
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let config: Self =
      toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    config.reject_removed_settings()?;
    Ok(config)
  }

  /// Refuses the keys that have no effect now. Then a user who set them sees an
  /// error, and the daemon does not ignore them without a message.
  fn reject_removed_settings(&self) -> Result<()> {
    let ghidra = &self.ghidra;
    if ghidra.java_tmp_dir.is_some() {
      bail!(
        "[ghidra].java_tmp_dir is not supported; Java temporary files use the runtime tmp directory"
      );
    }
    for (key, value) in [
      ("script_path", &ghidra.script_path),
      ("bridge_script", &ghidra.bridge_script),
    ] {
      if value.is_some() {
        bail!(
          "[ghidra].{key} is not supported; bridge runtime is embedded and its script \
           directory/name cannot be overridden"
        );
      }
    }
    Ok(())
  }

  /// Returns the total time for a session to become ready. This includes the
  /// process start, the import, the connection and the `ghidra.ready` handshake.
  /// It is also the default wait of `job.wait` and `session.open`.
  pub fn launch_timeout(&self) -> Duration {
    let timeouts = &self.timeouts;
    timeouts
      .process_spawn
      .saturating_add(timeouts.bridge_connect)
      .saturating_add(timeouts.agent_ready)
      .saturating_add(timeouts.analysis_import)
  }
}
