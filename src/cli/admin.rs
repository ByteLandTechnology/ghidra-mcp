// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The `setup`, `paths`, `config`, `session` and `job` commands.
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
    /// Attach an open GUI program by Bridge.java endpoint or outbound arguments.
    Attach {
        /// Optional local binary path, 32-character MD5, or ws:// endpoint URL.
        target: Option<String>,
        /// Loopback Bridge.java WebSocket URL, such as <ws://127.0.0.1:8765/ws/agent>.
        #[arg(long)]
        ws_url: Option<String>,
        /// Loopback Bridge.java WebSocket port, such as 8765.
        #[arg(long)]
        port: Option<u16>,
        /// Bearer token for a Bridge.java server.
        #[arg(long)]
        token: Option<String>,
        /// Display file name for the session.
        #[arg(long)]
        file_name: Option<String>,
        /// Wait until an outbound Bridge.java client connects.
        #[arg(long)]
        wait: bool,
        /// Maximum wait in milliseconds.
        #[arg(long)]
        timeout_ms: Option<u64>,
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

/// Extracts the bundled Ghidra scripts and JAR into a user script directory.
pub fn setup(dir: Option<PathBuf>, json: bool) -> Result<ExitCode> {
    let target = match dir {
        Some(path) => path,
        None => crate::paths::default_ghidra_scripts_dir()?,
    };
    let installed = crate::bridge::install_user_scripts(&target)?;
    if json {
        let files: Vec<String> = installed
            .files
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        print_json(&json!({
            "scriptDir": installed.directory.display().to_string(),
            "files": files,
        }))?;
    } else {
        out!("script_dir: {}", installed.directory.display());
        for file in &installed.files {
            out!("installed:  {}", file.display());
        }
    }
    Ok(ExitCode::SUCCESS)
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
            (call("ghidra_session", "open", None, params).await?, json)
        }
        SessionCommand::Attach {
            target,
            ws_url,
            port,
            token,
            file_name,
            wait,
            timeout_ms,
            json,
        } => {
            let value =
                attach_session(target, ws_url, port, token, file_name, wait, timeout_ms).await?;
            if json {
                print_json(&value)?;
            } else if let Some(args) = value["bridgeArgs"].as_str() {
                out!("{args}");
            } else {
                print_sessions(std::slice::from_ref(&value["session"]));
            }
            return Ok(ExitCode::SUCCESS);
        }
        SessionCommand::Close { md5, force, json } => {
            let params = json!({ "force": force });
            (
                call("ghidra_session", "close", Some(&md5), params).await?,
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

/// Returns `true` when `raw` starts with `ws://` or `wss://`.
fn looks_like_ws_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("ws://"))
        || trimmed
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("wss://"))
}

/// Resolves `session attach` arguments and calls `ghidra_session attach`.
async fn attach_session(
    target: Option<String>,
    mut ws_url: Option<String>,
    port: Option<u16>,
    token: Option<String>,
    file_name: Option<String>,
    wait: bool,
    timeout_ms: Option<u64>,
) -> Result<Value> {
    let mut md5 = None;
    let mut params = Map::new();
    params.insert("wait".into(), wait.into());
    if let Some(raw) = target {
        if looks_like_ws_url(&raw) {
            if ws_url.is_some() {
                bail!("pass a WebSocket URL either as TARGET or with `--ws-url`, not both");
            }
            ws_url = Some(raw);
        } else {
            let candidate = Path::new(&raw);
            if candidate.exists() {
                let canonical = candidate
                    .canonicalize()
                    .with_context(|| format!("cannot find {raw}"))?;
                params.insert("path".into(), canonical.display().to_string().into());
            } else if crate::project::normalize_md5(&raw).is_ok() {
                md5 = Some(raw);
            } else {
                let canonical = candidate
                    .canonicalize()
                    .with_context(|| format!("cannot find {raw}"))?;
                params.insert("path".into(), canonical.display().to_string().into());
            }
        }
    }
    if let Some(url) = ws_url {
        params.insert("wsUrl".into(), url.into());
    }
    if let Some(port) = port {
        params.insert("port".into(), port.into());
    }
    if let Some(token) = token {
        params.insert("token".into(), token.into());
    }
    if let Some(name) = file_name {
        params.insert("fileName".into(), name.into());
    }
    if let Some(timeout) = timeout_ms {
        params.insert("timeoutMs".into(), timeout.into());
    }
    call(
        "ghidra_session",
        "attach",
        md5.as_deref(),
        Value::Object(params),
    )
    .await
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
