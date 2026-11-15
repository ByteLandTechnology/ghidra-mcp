// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The `daemon` commands: run, start, stop, restart, status and logs.

use super::output::{self, print_json, print_table, text};
use super::parse_listen_address;
use crate::daemon::ProxyConnectionManager;
use anyhow::{Context, Result};
use clap::Subcommand;
use serde_json::{json, Map, Value};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

/// The HTTP listener of the daemon if `--listen` has no value.
const DEFAULT_LISTEN_ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 18489);

/// The exit status of `daemon status` when no daemon runs.
const NOT_RUNNING: u8 = 3;

/// The error text of a daemon from before `ghidra_daemon`.
const OLD_DAEMON: &str = "unknown tool: ghidra_daemon";

/// The time between two reads of the log for `daemon logs --follow`.
const FOLLOW_INTERVAL: Duration = Duration::from_millis(500);

/// The `daemon` commands.
#[derive(Subcommand)]
pub enum DaemonCommand {
    /// Run the daemon in the foreground until Ctrl-C, a stop signal or `daemon stop`.
    Run {
        /// The loopback address of the HTTP MCP and bridge listener.
        #[arg(long, value_parser = parse_listen_address)]
        listen: Option<SocketAddr>,
    },
    /// Start the daemon in the background, and wait until it is ready.
    Start {
        /// The loopback address of the HTTP MCP and bridge listener.
        #[arg(long, value_parser = parse_listen_address)]
        listen: Option<SocketAddr>,
    },
    /// Stop the daemon. The daemon closes all sessions first.
    Stop {
        /// Stop the daemon also if a session is live or a job runs.
        #[arg(long)]
        force: bool,
    },
    /// Stop the daemon, then start it again.
    Restart {
        /// Stop the daemon also if a session is live or a job runs.
        #[arg(long)]
        force: bool,
        /// The loopback address of the HTTP MCP and bridge listener.
        #[arg(long, value_parser = parse_listen_address)]
        listen: Option<SocketAddr>,
    },
    /// Write the state of the daemon. The exit status is 3 if no daemon runs.
    Status {
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Write the last lines of the daemon log.
    Logs {
        /// The number of lines to write.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Continue to write new lines until Ctrl-C.
        #[arg(short, long)]
        follow: bool,
    },
}

/// Runs one `daemon` command.
pub async fn run(command: DaemonCommand) -> Result<ExitCode> {
    match command {
        DaemonCommand::Run { listen } => {
            crate::daemon::run(listen.unwrap_or(DEFAULT_LISTEN_ADDRESS)).await?;
            Ok(ExitCode::SUCCESS)
        }
        DaemonCommand::Start { listen } => start(listen).await,
        DaemonCommand::Stop { force } => stop(force).await,
        DaemonCommand::Restart { force, listen } => {
            let code = stop(force).await?;
            if code != ExitCode::SUCCESS {
                return Ok(code);
            }
            start(listen).await
        }
        DaemonCommand::Status { json } => status(json).await,
        DaemonCommand::Logs { lines, follow } => logs(lines, follow),
    }
}

/// Calls a `ghidra_daemon` operation through a connection that is open.
async fn call(manager: &ProxyConnectionManager, operation: &str, params: Value) -> Result<Value> {
    let Value::Object(params) = params else {
        unreachable!("the caller gives a JSON object");
    };
    let mut arguments = Map::new();
    arguments.insert("operation".into(), operation.into());
    arguments.insert("params".into(), Value::Object(params));
    let result = manager.call_tool("ghidra_daemon".into(), arguments).await?;
    output::tool_value(result)
}

/// Runs `daemon start`.
async fn start(listen: Option<SocketAddr>) -> Result<ExitCode> {
    let manager = ProxyConnectionManager::global()?;
    let started = manager.start(listen).await?;
    let status = call(&manager, "status", json!({})).await?;
    if started {
        out!("Daemon started.");
    } else {
        out!("Daemon runs already.");
        if listen.is_some() {
            eprintln!("--listen has no effect on a daemon that runs. Use `daemon restart`.");
        }
    }
    print_status(&status);
    Ok(ExitCode::SUCCESS)
}

/// Runs `daemon stop`. If no daemon runs, the command succeeds.
async fn stop(force: bool) -> Result<ExitCode> {
    let manager = ProxyConnectionManager::global()?;
    if !manager.connect_existing().await? {
        out!("Daemon: not running");
        return Ok(ExitCode::SUCCESS);
    }
    let result = call(&manager, "shutdown", json!({ "force": force })).await;
    if let Err(error) = result {
        if error.to_string().contains(OLD_DAEMON) {
            return stop_old_daemon(&manager).await;
        }
        eprintln!("Daemon was not stopped: {error}");
        if !force {
            eprintln!("Use --force to stop it, and all its sessions and jobs.");
        }
        return Ok(ExitCode::FAILURE);
    }
    manager.wait_until_stopped().await?;
    out!("Daemon stopped.");
    Ok(ExitCode::SUCCESS)
}

/// Stops a daemon from before `ghidra_daemon` with a stop signal. Such a
/// daemon closes its sessions when it gets the signal. It does not check `--force`.
/// On Windows, it only writes a hint. Thus that version has no `await`.
#[cfg_attr(windows, allow(clippy::unused_async))]
async fn stop_old_daemon(manager: &ProxyConnectionManager) -> Result<ExitCode> {
    let pid = manager
        .daemon_pid()?
        .context("the older daemon wrote no process ID")?;
    #[cfg(unix)]
    {
        let pid = libc::pid_t::try_from(pid).context("process ID out of range")?;
        // SAFETY: `kill` has no memory effects. It only sends a signal to the process.
        if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
            return Err(io::Error::last_os_error()).context("sending SIGTERM to the daemon");
        }
        manager.wait_until_stopped().await?;
        out!("Daemon stopped (older version, stopped with SIGTERM).");
        Ok(ExitCode::SUCCESS)
    }
    #[cfg(windows)]
    {
        eprintln!(
            "The daemon (pid {pid}) is an older version that has no stop operation. \
             Stop it with `Stop-Process -Id {pid}`."
        );
        Ok(ExitCode::FAILURE)
    }
}

/// Runs `daemon status`.
async fn status(json: bool) -> Result<ExitCode> {
    let manager = ProxyConnectionManager::global()?;
    if !manager.connect_existing().await? {
        if json {
            print_json(&json!({ "running": false }))?;
        } else {
            out!("Daemon: not running");
        }
        return Ok(ExitCode::from(NOT_RUNNING));
    }
    let mut status = match call(&manager, "status", json!({})).await {
        Err(error) if error.to_string().contains(OLD_DAEMON) => {
            let pid = manager.daemon_pid()?;
            if json {
                print_json(&json!({ "running": true, "daemon": { "pid": pid } }))?;
            } else {
                let pid = pid.map_or_else(|| "-".to_string(), |pid| pid.to_string());
                out!("Daemon:   running (pid {pid}, older version)");
                out!("Use `daemon restart` to use the daemon of this version.");
            }
            return Ok(ExitCode::SUCCESS);
        }
        result => result?,
    };
    if json {
        if let Value::Object(object) = &mut status {
            object.insert("running".into(), true.into());
        }
        print_json(&status)?;
    } else {
        print_status(&status);
    }
    Ok(ExitCode::SUCCESS)
}

/// Writes the result of `ghidra_daemon status` as text.
fn print_status(status: &Value) {
    let daemon = &status["daemon"];
    out!(
        "Daemon:   running (pid {}, version {})",
        text(daemon, "pid"),
        text(daemon, "version")
    );
    out!("MCP URL:  {}", text(daemon, "mcpUrl"));
    let uptime = daemon["uptimeSeconds"].as_u64().unwrap_or_default();
    out!("Uptime:   {}", output::duration(uptime));
    let sessions = status["sessions"].as_array().map_or(&[][..], Vec::as_slice);
    let jobs = status["jobs"].as_array().map_or(&[][..], Vec::as_slice);
    out!("Sessions: {}", sessions.len());
    out!("Jobs:     {} running", jobs.len());
    if !sessions.is_empty() {
        out!();
        super::admin::print_sessions(sessions);
    }
    if !jobs.is_empty() {
        out!();
        let rows: Vec<Vec<String>> = jobs
            .iter()
            .map(|job| vec![text(job, "id"), text(job, "kind"), text(job, "md5")])
            .collect();
        print_table(&["JOB", "KIND", "MD5"], &rows);
    }
}

/// Runs `daemon logs`.
fn logs(lines: usize, follow: bool) -> Result<ExitCode> {
    let path = crate::paths::runtime_dir()?.join("daemon.log");
    let mut file =
        File::open(&path).with_context(|| format!("no daemon log at {}", path.display()))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .with_context(|| format!("reading {}", path.display()))?;
    let start = content.lines().count().saturating_sub(lines);
    let mut stdout = io::stdout().lock();
    for line in content.lines().skip(start) {
        writeln!(stdout, "{line}")?;
    }
    stdout.flush()?;
    drop(stdout);
    if follow {
        follow_log(&path, content.len() as u64)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Writes the lines that the daemon adds to its log, until the process stops.
/// After a rotation, the file is shorter. Then it writes the new file from its start.
fn follow_log(path: &Path, mut position: u64) -> Result<()> {
    loop {
        std::thread::sleep(FOLLOW_INTERVAL);
        let Ok(mut file) = File::open(path) else {
            continue;
        };
        let length = file.metadata()?.len();
        if length < position {
            position = 0;
        }
        if length == position {
            continue;
        }
        file.seek(SeekFrom::Start(position))?;
        let mut added = Vec::new();
        file.read_to_end(&mut added)?;
        position += added.len() as u64;
        let mut stdout = io::stdout().lock();
        stdout.write_all(&added)?;
        stdout.flush()?;
    }
}
