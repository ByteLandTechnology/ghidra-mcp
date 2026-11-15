// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The command-line arguments and the run modes.
//!
//! Without a subcommand, the process serves MCP through stdio as a proxy to the
//! daemon. The subcommands manage the daemon, its files, its sessions and its
//! jobs, or make one tool call.

/// Writes one line to stdout, as `println!` does. If the reader closed the
/// pipe, for example `head`, the process stops with status 0 instead of a panic.
macro_rules! out {
    () => {
        $crate::cli::output::line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::cli::output::line(format_args!($($arg)*))
    };
}

mod admin;
mod daemon;
mod output;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::{Map, Value};
use std::io;
use std::net::SocketAddr;
use std::process::ExitCode;

use crate::mcp::ToolServer;

/// The command-line arguments.
#[derive(Parser)]
#[command(
    name = "ghidra-mcp",
    version,
    about = "Ghidra analysis tools through MCP and a command-line interface",
    long_about = concat!(
        "Ghidra analysis tools through MCP and a command-line interface.\n\n",
        "Without a command, ghidra-mcp serves MCP through stdio. MCP clients use this mode. ",
        "If the shared daemon does not run, ghidra-mcp starts it."
    )
)]
struct Cli {
    /// A one-time action instead of the stdio MCP server.
    #[command(subcommand)]
    command: Option<Command>,
}

/// The one-time actions.
#[derive(Subcommand)]
enum Command {
    /// Run, start, stop or examine the shared daemon.
    #[command(subcommand)]
    Daemon(daemon::DaemonCommand),

    /// Write the locations of the files and directories of ghidra-mcp.
    Paths {
        /// Write JSON instead of text.
        #[arg(long)]
        json: bool,
    },

    /// Examine, change or check config.toml.
    #[command(subcommand)]
    Config(admin::ConfigCommand),

    /// Open, list, examine or close the sessions of the daemon.
    #[command(subcommand)]
    Session(admin::SessionCommand),

    /// List, examine or wait for the background jobs of the daemon.
    #[command(subcommand)]
    Job(admin::JobCommand),

    /// Write the tool definitions, but do not start the daemon.
    Tools,

    /// Call a tool through the shared daemon.
    Call {
        /// The tool name, for example `ghidra_session`. `tools` lists all tools.
        tool: String,
        /// A JSON object with the tool arguments.
        #[arg(default_value = "{}", value_parser = parse_arguments)]
        arguments: Map<String, Value>,
    },
}

/// Reads the command line, runs the selected mode, and returns the process
/// exit status. It writes the errors to stderr.
pub async fn run() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // The exit codes of clap are 0 (help, version) or 2 (usage errors).
            let code = u8::try_from(error.exit_code()).unwrap_or(2);
            let _ = error.print();
            return ExitCode::from(code);
        }
    };

    match execute(cli).await {
        Ok(code) => code,
        Err(error) => {
            crate::process::log_daemon(&format!("{error:#}"));
            ExitCode::FAILURE
        }
    }
}

/// Runs one mode.
async fn execute(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        None => {
            crate::mcp::serve_stdio().await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Daemon(command)) => daemon::run(command).await,
        Some(Command::Paths { json }) => admin::paths(json),
        Some(Command::Config(command)) => admin::config(command),
        Some(Command::Session(command)) => admin::session(command).await,
        Some(Command::Job(command)) => admin::job(command).await,
        Some(Command::Tools) => {
            output::write_json(io::stdout().lock(), &ToolServer::tools())?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Call { tool, arguments }) => {
            let result = ToolServer::proxy()?.call(tool, arguments).await;
            output::display_call(result)
        }
    }
}

/// Reads the `call` arguments. They must be a JSON object.
fn parse_arguments(raw: &str) -> Result<Map<String, Value>, String> {
    serde_json::from_str(raw).map_err(|error| format!("arguments must be a JSON object: {error}"))
}

/// Reads `--listen`. It accepts only loopback addresses, because other hosts
/// must not get access to the HTTP endpoint and the bridge WebSocket.
fn parse_listen_address(raw: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = raw
        .parse()
        .map_err(|error| format!("expected IP:PORT: {error}"))?;
    if !address.ip().is_loopback() {
        return Err("the daemon listener must use a loopback IP address".to_string());
    }
    Ok(address)
}

#[cfg(test)]
mod tests;
