// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The `paths`, `config`, `session` and `job` commands.
//!
//! The session and job commands call the domain tools through the daemon,
//! the same as `call`. If necessary, they start the daemon.

use super::output::{self, print_json, print_table, text};
use crate::config::McpConfig;
use crate::import::{is_gpr_path, OpenOptions};
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
    /// Open a session for a binary or `.gpr` project on this computer.
    Open {
        /// The binary or `.gpr` file.
        path: PathBuf,
        /// Program name or project path in an attached `.gpr` project.
        #[arg(long)]
        program_name: Option<String>,
        /// Ghidra language ID for `-processor` during binary import.
        #[arg(long)]
        processor: Option<String>,
        /// Ghidra compiler specification ID for `-cspec`.
        #[arg(long)]
        compiler_spec: Option<String>,
        /// Ghidra loader class name for `-loader`.
        #[arg(long)]
        loader: Option<String>,
        /// Hexadecimal load address for `-loader-baseAddr`.
        #[arg(long)]
        base_address: Option<String>,
        /// Replace the saved binary project and run `-import` again.
        #[arg(long)]
        reimport: bool,
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
    /// Create, list, or restore checkpoints of a session.
    #[command(subcommand)]
    Checkpoint(CheckpointCommand),
    /// Reset a session to a clean binary import.
    Reset {
        /// The MD5 of the session.
        md5: String,
        /// Start a fresh Ghidra project after the reset.
        #[arg(long)]
        open: bool,
        /// Wait until the reopened session is ready.
        #[arg(long)]
        wait: bool,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Delete a session, its project, its checkpoints, and its logs.
    Delete {
        /// The MD5 of the session.
        md5: String,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// The `session checkpoint` subcommands.
#[derive(Subcommand)]
pub enum CheckpointCommand {
    /// Save the active session and create a checkpoint snapshot.
    Create {
        /// The MD5 of the session.
        md5: String,
        /// Optional human-readable label for the checkpoint.
        #[arg(long)]
        name: Option<String>,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// List checkpoints of a session from newest to oldest.
    List {
        /// The MD5 of the session.
        md5: String,
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },
    /// Restore a checkpoint and relaunch the session.
    Restore {
        /// The MD5 of the session.
        md5: String,
        /// Checkpoint ID to restore. Omit to restore the newest checkpoint.
        #[arg(long, conflicts_with = "name")]
        id: Option<String>,
        /// Checkpoint name to restore when `--id` is omitted.
        #[arg(long)]
        name: Option<String>,
        /// Do not wait for the relaunched session.
        #[arg(long)]
        no_wait: bool,
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

/// Validates CLI `session open` arguments and builds `ghidra_session open` parameters.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI subcommand maps 1:1 to session open options"
)]
pub(super) fn build_open_params(
    path: &Path,
    program_name: Option<&str>,
    processor: Option<&str>,
    compiler_spec: Option<&str>,
    loader: Option<&str>,
    base_address: Option<&str>,
    reimport: bool,
    wait: bool,
) -> Result<Value> {
    let options = OpenOptions::from_raw(
        processor,
        compiler_spec,
        loader,
        base_address,
        reimport,
        program_name,
    )?;
    options.validate_for_target(is_gpr_path(path))?;
    options.import.validate_complete()?;
    // The daemon has a different current directory. Send an absolute path.
    let canonical = path
        .canonicalize()
        .with_context(|| format!("cannot find {}", path.display()))?;
    options.validate_for_target(is_gpr_path(&canonical))?;
    let mut params = Map::new();
    params.insert("path".into(), canonical.display().to_string().into());
    params.insert("wait".into(), wait.into());
    if let Some(program_name) = options.program_name {
        params.insert("programName".into(), program_name.into());
    }
    if let Some(processor) = options.import.processor {
        params.insert("processor".into(), processor.into());
    }
    if let Some(compiler_spec) = options.import.compiler_spec {
        params.insert("compilerSpec".into(), compiler_spec.into());
    }
    if let Some(loader) = options.import.loader {
        params.insert("loader".into(), loader.into());
    }
    if let Some(base_address) = options.import.base_address {
        params.insert("baseAddress".into(), base_address.into());
    }
    if options.reimport {
        params.insert("reimport".into(), true.into());
    }
    Ok(Value::Object(params))
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
        SessionCommand::Open {
            path,
            program_name,
            processor,
            compiler_spec,
            loader,
            base_address,
            reimport,
            wait,
            json,
        } => {
            let params = build_open_params(
                &path,
                program_name.as_deref(),
                processor.as_deref(),
                compiler_spec.as_deref(),
                loader.as_deref(),
                base_address.as_deref(),
                reimport,
                wait,
            )?;
            (call("ghidra_session", "open", None, params).await?, json)
        }
        SessionCommand::Close { md5, force, json } => {
            let params = json!({ "force": force });
            (
                call("ghidra_session", "close", Some(&md5), params).await?,
                json,
            )
        }
        SessionCommand::Checkpoint(subcommand) => return session_checkpoint(subcommand).await,
        SessionCommand::Reset {
            md5,
            open,
            wait,
            json,
        } => {
            let params = json!({ "open": open, "wait": wait });
            (
                call("ghidra_session", "reset", Some(&md5), params).await?,
                json,
            )
        }
        SessionCommand::Delete { md5, json } => {
            let value = call("ghidra_session", "delete", Some(&md5), json!({})).await?;
            if json {
                print_json(&value)?;
            } else {
                out!("Deleted session {}.", text(&value, "md5"));
            }
            return Ok(ExitCode::SUCCESS);
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

/// Runs one `session checkpoint` subcommand.
async fn session_checkpoint(command: CheckpointCommand) -> Result<ExitCode> {
    match command {
        CheckpointCommand::Create { md5, name, json } => {
            let mut params = json!({});
            if let Some(label) = name {
                params["name"] = label.into();
            }
            let value = call("ghidra_session", "checkpoint.create", Some(&md5), params).await?;
            if json {
                print_json(&value)?;
            } else {
                print_checkpoints(std::slice::from_ref(&value["checkpoint"]));
            }
        }
        CheckpointCommand::List { md5, json } => {
            let value = call("ghidra_session", "checkpoint.list", Some(&md5), json!({})).await?;
            if json {
                print_json(&value)?;
            } else if let Some(items) = value["items"].as_array() {
                print_checkpoints(items);
            }
        }
        CheckpointCommand::Restore {
            md5,
            id,
            name,
            no_wait,
            json,
        } => {
            let mut params = json!({ "wait": !no_wait });
            if let Some(target_id) = id {
                params["id"] = target_id.into();
            }
            if let Some(target_name) = name {
                params["name"] = target_name.into();
            }
            let value = call("ghidra_session", "checkpoint.restore", Some(&md5), params).await?;
            if json {
                print_json(&value)?;
            } else {
                out!(
                    "Restored checkpoint {} for session {}.",
                    text(&value["checkpoint"], "id"),
                    text(&value, "md5")
                );
                print_sessions(std::slice::from_ref(&value["session"]));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Writes checkpoint summaries as a table.
fn print_checkpoints(items: &[Value]) {
    if items.is_empty() {
        out!("No checkpoints.");
        return;
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|item| {
            vec![
                text(item, "id"),
                text(item, "createdAt"),
                item.get("sizeBytes")
                    .and_then(Value::as_u64)
                    .map_or_else(|| "-".to_string(), |size| format!("{size} B")),
                text(item, "name"),
            ]
        })
        .collect();
    print_table(&["ID", "CREATED", "SIZE", "NAME"], &rows);
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
