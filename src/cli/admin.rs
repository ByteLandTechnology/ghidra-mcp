// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The `paths`, `config`, `session` and `job` commands.
//!
//! The session and job commands call the domain tools through the daemon,
//! the same as `call`. If necessary, they start the daemon.

use super::output::{self, print_json, print_table, text};
use crate::config::McpConfig;
use crate::mcp::ToolServer;
use crate::paths::McpPaths;
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The `config` commands.
#[derive(Clone, Copy, Subcommand)]
pub enum ConfigCommand {
    /// Write the path of config.toml.
    Path,
    /// Write the text of config.toml. If the file does not exist, make it first.
    Show,
    /// Open config.toml in $VISUAL or $EDITOR, then check it.
    Edit,
    /// Make sure that config.toml is valid.
    Check,
}

/// The `session` commands.
#[derive(Subcommand)]
pub enum SessionCommand {
    /// List the sessions of the daemon.
    List {
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Write one session.
    Get {
        /// The MD5 of the session.
        md5: String,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Open a session for a file on this computer.
    Open {
        /// The binary file.
        path: PathBuf,
        /// Wait until the session is ready.
        #[arg(long)]
        wait: bool,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Close a session. The bridge saves the program, then stops.
    Close {
        /// The MD5 of the session.
        md5: String,
        /// Kill the process. Do not tell the bridge to save and stop.
        #[arg(long)]
        force: bool,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// The `job` commands.
#[derive(Subcommand)]
pub enum JobCommand {
    /// List the background jobs that the daemon keeps.
    List {
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Write one job.
    Get {
        /// The job ID.
        id: String,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Wait until a job finishes, then write it.
    Wait {
        /// The job ID.
        id: String,
        /// The maximum wait in milliseconds, instead of the launch timeout.
        #[arg(long)]
        timeout_ms: Option<u64>,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// Runs `paths`.
pub fn paths(json: bool) -> Result<ExitCode> {
    let paths = McpPaths::new()?;
    let home = paths
        .config_toml
        .parent()
        .context("config.toml has no parent directory")?;
    let entries = [
        ("home", home.to_path_buf()),
        ("config", paths.config_toml.clone()),
        ("projects", paths.projects_dir.clone()),
        ("runtime", paths.runtime_dir.clone()),
        ("log", paths.runtime_dir.join("daemon.log")),
        ("server", paths.runtime_dir.join("server.json")),
    ];
    if json {
        let object: Map<String, Value> = entries
            .iter()
            .map(|(name, path)| ((*name).to_string(), path.display().to_string().into()))
            .collect();
        print_json(&object)?;
    } else {
        for (name, path) in &entries {
            out!("{:<9} {}", format!("{name}:"), path.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs one `config` command.
pub fn config(command: ConfigCommand) -> Result<ExitCode> {
    let paths = McpPaths::new()?;
    let path = &paths.config_toml;
    match command {
        ConfigCommand::Path => out!("{}", path.display()),
        ConfigCommand::Show => {
            // The load makes the default file if it does not exist.
            let _ = McpConfig::load_or_create(&paths);
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            out!("{}", content.trim_end_matches('\n'));
        }
        ConfigCommand::Edit => {
            let _ = McpConfig::load_or_create(&paths);
            edit(path)?;
            return Ok(check(&paths));
        }
        ConfigCommand::Check => return Ok(check(&paths)),
    }
    Ok(ExitCode::SUCCESS)
}

/// Loads config.toml and reports the result.
fn check(paths: &McpPaths) -> ExitCode {
    match McpConfig::load_or_create(paths) {
        Ok(_) => {
            out!("{}: OK", paths.config_toml.display());
            out!("A daemon that runs uses the new values after `daemon restart`.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

/// Opens `path` in the editor of the user, and waits until the editor stops.
fn edit(path: &Path) -> Result<()> {
    let editor = ["VISUAL", "EDITOR"]
        .into_iter()
        .find_map(|name| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| if cfg!(windows) { "notepad" } else { "vi" }.to_string());
    // The variable can contain arguments, for example `code --wait`.
    let mut words = editor.split_whitespace();
    let program = words.next().context("the editor command is empty")?;
    let status = std::process::Command::new(program)
        .args(words)
        .arg(path)
        .status()
        .with_context(|| format!("starting the editor `{editor}`"))?;
    if !status.success() {
        bail!("the editor `{editor}` stopped with {status}");
    }
    Ok(())
}

/// Calls a domain tool through the daemon and returns the structured result.
async fn call(tool: &str, operation: &str, md5: Option<&str>, params: Value) -> Result<Value> {
    let mut arguments = Map::new();
    arguments.insert("operation".into(), operation.into());
    if let Some(md5) = md5 {
        arguments.insert("md5".into(), md5.into());
    }
    arguments.insert("params".into(), params);
    let result = ToolServer::proxy()?.call(tool.into(), arguments).await;
    output::tool_value(result)
}

/// Runs one `session` command.
pub async fn session(command: SessionCommand) -> Result<ExitCode> {
    let (value, json) = match command {
        SessionCommand::List { json } => {
            (call("ghidra_session", "list", None, json!({})).await?, json)
        }
        SessionCommand::Get { md5, json } => (
            call("ghidra_session", "get", Some(&md5), json!({})).await?,
            json,
        ),
        SessionCommand::Open { path, wait, json } => {
            // The daemon has a different current directory. Send an absolute path.
            let path = path
                .canonicalize()
                .with_context(|| format!("cannot find {}", path.display()))?;
            let params = json!({ "path": path.display().to_string(), "wait": wait });
            (
                call("ghidra_session_write", "open", None, params).await?,
                json,
            )
        }
        SessionCommand::Close { md5, force, json } => {
            let params = json!({ "force": force });
            (
                call("ghidra_session_write", "close", Some(&md5), params).await?,
                json,
            )
        }
    };
    if json {
        print_json(&value)?;
    } else if let Some(sessions) = value["sessions"].as_array() {
        print_sessions(sessions);
    } else {
        print_sessions(std::slice::from_ref(&value["session"]));
    }
    Ok(ExitCode::SUCCESS)
}

/// Writes session summaries as a table.
pub fn print_sessions(sessions: &[Value]) {
    if sessions.is_empty() {
        out!("No sessions.");
        return;
    }
    let rows: Vec<Vec<String>> = sessions
        .iter()
        .map(|session| {
            vec![
                text(session, "md5"),
                text(session, "status"),
                text(session, "connected"),
                text(session, "fileName"),
            ]
        })
        .collect();
    print_table(&["MD5", "STATUS", "CONNECTED", "FILE"], &rows);
}

/// Runs one `job` command.
pub async fn job(command: JobCommand) -> Result<ExitCode> {
    let (value, json) = match command {
        JobCommand::List { json } => (call("ghidra_job", "list", None, json!({})).await?, json),
        JobCommand::Get { id, json } => {
            let params = json!({ "jobId": id });
            (call("ghidra_job", "get", None, params).await?, json)
        }
        JobCommand::Wait {
            id,
            timeout_ms,
            json,
        } => {
            let mut params = json!({ "jobId": id });
            if let Some(timeout) = timeout_ms {
                params["timeoutMs"] = timeout.into();
            }
            (call("ghidra_job", "wait", None, params).await?, json)
        }
    };
    if json {
        print_json(&value)?;
        return Ok(ExitCode::SUCCESS);
    }
    let jobs = match value["jobs"].as_array() {
        Some(jobs) => jobs.clone(),
        None => vec![value["job"].clone()],
    };
    if jobs.is_empty() {
        out!("No jobs.");
        return Ok(ExitCode::SUCCESS);
    }
    let rows: Vec<Vec<String>> = jobs
        .iter()
        .map(|job| {
            vec![
                text(job, "id"),
                text(job, "kind"),
                text(job, "status"),
                text(job, "md5"),
            ]
        })
        .collect();
    print_table(&["JOB", "KIND", "STATUS", "MD5"], &rows);
    for job in &jobs {
        if let Some(error) = job.get("error").filter(|error| !error.is_null()) {
            out!("{}: {}", text(job, "id"), error);
        }
    }
    Ok(ExitCode::SUCCESS)
}
