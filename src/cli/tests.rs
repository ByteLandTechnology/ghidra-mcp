// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of the command-line parser.

use super::admin::{JobCommand, SessionCommand};
use super::daemon::DaemonCommand;
use super::{Cli, Command};
use clap::{CommandFactory, Parser};

/// Parses the arguments after the program name.
fn parse(arguments: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(std::iter::once("ghidra-mcp").chain(arguments.iter().copied()))
}

/// Makes sure that the clap definition has no conflicts.
#[test]
fn command_definition_is_valid() {
    Cli::command().debug_assert();
}

/// Makes sure that no arguments select the stdio server.
#[test]
fn no_arguments_select_stdio() {
    assert!(parse(&[]).unwrap().command.is_none());
}

/// Makes sure that `daemon run` replaces `--daemon`, and that `--listen` needs loopback.
#[test]
fn daemon_run_replaces_the_daemon_flag() {
    let cli = parse(&["daemon", "run", "--listen", "127.0.0.1:0"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Daemon(DaemonCommand::Run { listen: Some(_) }))
    ));
    assert_eq!(parse(&["--daemon"]).err().unwrap().exit_code(), 2);
    assert!(parse(&["daemon", "run", "--listen", "0.0.0.0:1"]).is_err());
}

/// Makes sure that the management commands parse their arguments.
#[test]
fn management_commands_parse() {
    let cli = parse(&["daemon", "stop", "--force"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Daemon(DaemonCommand::Stop { force: true }))
    ));
    let cli = parse(&["daemon", "logs", "-n", "5", "-f"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Daemon(DaemonCommand::Logs {
            lines: 5,
            follow: true
        }))
    ));
    let cli = parse(&["session", "close", "0123", "--force", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Session(SessionCommand::Close {
            force: true,
            json: true,
            ..
        }))
    ));
    let cli = parse(&["job", "wait", "id", "--timeout-ms", "10"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Job(JobCommand::Wait {
            timeout_ms: Some(10),
            ..
        }))
    ));
    assert!(parse(&["paths", "--json"]).is_ok());
    assert!(parse(&["config", "check"]).is_ok());
    assert!(parse(&["call", "ghidra_help", "[]"]).is_err());
}

/// Makes sure that the durations have a short text form.
#[test]
fn durations_are_short() {
    assert_eq!(super::output::duration(5), "5s");
    assert_eq!(super::output::duration(65), "1m 5s");
    assert_eq!(super::output::duration(3725), "1h 2m 5s");
}

/// Makes sure that `tool_value` reads structured data without `content` and keeps text fallbacks.
#[test]
fn tool_value_handles_empty_content_and_unstructured_fallback() {
    use rmcp::model::{CallToolResult, ContentBlock};
    use serde_json::json;

    let mut ok = CallToolResult::success(Vec::new());
    ok.structured_content = Some(json!({ "sessions": [] }));
    assert_eq!(
        super::output::tool_value(ok).unwrap(),
        json!({ "sessions": [] })
    );

    let mut structured_err = CallToolResult::error(Vec::new());
    structured_err.structured_content = Some(json!({
        "response": { "error": { "message": "daemon is shutting down" } }
    }));
    assert_eq!(
        super::output::tool_value(structured_err)
            .unwrap_err()
            .to_string(),
        "daemon is shutting down"
    );

    let legacy_err = CallToolResult::error(vec![ContentBlock::text("unknown tool: ghidra_daemon")]);
    assert_eq!(
        super::output::tool_value(legacy_err)
            .unwrap_err()
            .to_string(),
        "unknown tool: ghidra_daemon"
    );
}
