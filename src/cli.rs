// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The command-line arguments, and the three run modes: daemon, stdio proxy and CLI.

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmcp::model::CallToolResult;
use serde_json::{Map, Value};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::process::ExitCode;

use crate::mcp::ToolServer;

/// The HTTP listener of the daemon if `--listen` has no value.
const DEFAULT_LISTEN_ADDRESS: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 18489);

/// The command-line arguments. Without a subcommand or `--daemon`, the process
/// serves MCP through stdio as a proxy to the daemon.
#[derive(Parser)]
#[command(
    name = "ghidra-mcp",
    version,
    about = "Ghidra analysis tools through MCP and a command-line interface",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    /// Run the shared daemon in the foreground.
    #[arg(long)]
    daemon: bool,

    /// Set the loopback address of the HTTP MCP and bridge listener in daemon mode.
    #[arg(long, requires = "daemon", value_parser = parse_listen_address)]
    listen: Option<SocketAddr>,

    /// A one-time CLI action instead of an MCP server.
    #[command(subcommand)]
    command: Option<Command>,
}

/// CLI actions that run one time.
#[derive(Subcommand)]
enum Command {
    /// Write the tool definitions, but do not start the daemon.
    Tools,

    /// Call a tool through the shared daemon.
    Call {
        /// The tool name. `ghidra` is the only tool.
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

/// Runs one mode. Only `call` can return a nonzero status without an error.
async fn execute(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Some(Command::Tools) => {
            write_json(io::stdout().lock(), &ToolServer::tools())?;
        }
        Some(Command::Call { tool, arguments }) => {
            let result = ToolServer::proxy()?.call(tool, arguments).await;
            return display_call(result);
        }
        None if cli.daemon => {
            crate::daemon::run(cli.listen.unwrap_or(DEFAULT_LISTEN_ADDRESS)).await?;
        }
        None => crate::mcp::serve_stdio().await?,
    }
    Ok(ExitCode::SUCCESS)
}

/// Writes a tool result. For a success, it writes the structured result to
/// stdout. For a failure, it writes the structured result or the error text to stderr.
fn display_call(result: CallToolResult) -> Result<ExitCode> {
    if result.is_error == Some(true) {
        if let Some(value) = &result.structured_content {
            write_json(io::stderr().lock(), value)?;
        } else {
            let mut stderr = io::stderr().lock();
            for content in &result.content {
                if let Some(text) = content.as_text() {
                    writeln!(stderr, "{}", text.text)?;
                }
            }
            stderr.flush()?;
        }
        Ok(ExitCode::FAILURE)
    } else {
        write_json(
            io::stdout().lock(),
            &result.structured_content.unwrap_or(Value::Null),
        )?;
        Ok(ExitCode::SUCCESS)
    }
}

/// Writes `value` as formatted JSON, with a newline at the end.
fn write_json(mut writer: impl Write, value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
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
