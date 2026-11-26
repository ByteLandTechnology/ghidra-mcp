// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Tests of the command-line parser.

use super::admin::{CheckpointCommand, JobCommand, SessionCommand};
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
    let cli = parse(&["job", "cancel", "id", "--wait", "--timeout-ms", "10"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Job(JobCommand::Cancel {
            wait: true,
            timeout_ms: Some(10),
            ..
        }))
    ));
    assert!(parse(&["paths", "--json"]).is_ok());
    assert!(parse(&["config", "check"]).is_ok());
    assert!(parse(&["call", "ghidra_help", "[]"]).is_err());
    let cli = parse(&["session", "checkpoint", "create", "0123", "--name", "base"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Session(SessionCommand::Checkpoint(
            CheckpointCommand::Create { .. }
        )))
    ));
    let cli = parse(&["session", "reset", "0123", "--open", "--wait"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Session(SessionCommand::Reset {
            open: true,
            wait: true,
            ..
        }))
    ));
    assert!(parse(&["session", "delete", "0123"]).is_ok());
}

/// Makes sure that `session attach` and `setup` parse their arguments.
#[test]
fn attach_and_setup_commands_parse() {
    let cli = parse(&["session", "attach"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Session(SessionCommand::Attach {
            target: None,
            ws_url: None,
            port: None,
            token: None,
            file_name: None,
            wait: false,
            timeout_ms: None,
            json: false,
        }))
    ));
    let cli = parse(&[
        "session",
        "attach",
        "/tmp/sample.bin",
        "--file-name",
        "sample.bin",
        "--wait",
        "--timeout-ms",
        "5000",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Session(SessionCommand::Attach {
            target: Some(_),
            ws_url: None,
            port: None,
            token: None,
            file_name: Some(_),
            wait: true,
            timeout_ms: Some(5000),
            json: true,
        }))
    ));
    let cli = parse(&[
        "session", "attach", "--port", "8766", "--token", "secret", "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Session(SessionCommand::Attach {
            target: None,
            ws_url: None,
            port: Some(8766),
            token: Some(_),
            json: true,
            ..
        }))
    ));
    let cli = parse(&["setup"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Setup {
            dir: None,
            json: false,
        })
    ));
    let cli = parse(&["setup", "/tmp/scripts", "--json"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Setup {
            dir: Some(_),
            json: true,
        })
    ));
}

/// Makes sure that `install_user_scripts` writes the GUI scripts and JAR.
#[test]
fn setup_extracts_launcher_scripts_and_jar() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("ghidra_scripts");
    let installed = crate::bridge::install_user_scripts(&target).unwrap();
    assert_eq!(installed.directory, target);
    for path in &installed.files {
        let metadata = std::fs::metadata(path).unwrap();
        assert!(
            metadata.is_file() && metadata.len() > 0,
            "{}",
            path.display()
        );
    }
    let bridge_script = std::fs::read_to_string(target.join("Bridge.java")).unwrap();
    let mcp_script = std::fs::read_to_string(target.join("GhidraMcp.java")).unwrap();
    assert!(bridge_script.contains("startFromScript"));
    assert!(mcp_script.contains("startMcpFromScript"));
    assert!(bridge_script.contains("ghidra-bridge.jar"));
    assert!(mcp_script.contains("ghidra-bridge.jar"));

    let again = crate::bridge::install_user_scripts(&target).unwrap();
    assert_eq!(again.files, installed.files);
}

/// Makes sure that the durations have a short text form.
#[test]
fn durations_are_short() {
    assert_eq!(super::output::duration(5), "5s");
    assert_eq!(super::output::duration(65), "1m 5s");
    assert_eq!(super::output::duration(3725), "1h 2m 5s");
}

/// Checks CLI `session open` arguments and validation for firmware flags and `.gpr` paths.
#[test]
fn session_open_flags_parse_and_validate() {
    let cli = parse(&[
        "session",
        "open",
        "firmware.bin",
        "--processor",
        "ARM:LE:32:Cortex",
        "--compiler-spec",
        "default",
        "--loader",
        "BinaryLoader",
        "--base-address",
        "08000000",
        "--reimport",
        "--wait",
        "--json",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Session(SessionCommand::Open {
            reimport: true,
            wait: true,
            json: true,
            ..
        }))
    ));

    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("fw.bin");
    std::fs::write(&bin, [0u8; 4]).unwrap();
    let gpr = temp.path().join("board.gpr");
    std::fs::write(&gpr, "<project/>").unwrap();

    let params = super::admin::build_open_params(
        &bin,
        None,
        Some("ARM:LE:32:Cortex"),
        Some("default"),
        Some("BinaryLoader"),
        Some("08000000"),
        true,
        true,
    )
    .unwrap();
    assert_eq!(params["processor"], "ARM:LE:32:Cortex");
    assert_eq!(params["compilerSpec"], "default");
    assert_eq!(params["loader"], "BinaryLoader");
    assert_eq!(params["baseAddress"], "0x08000000");
    assert_eq!(params["reimport"], true);

    assert!(super::admin::build_open_params(
        &bin,
        Some("app"),
        None,
        None,
        None,
        None,
        false,
        false,
    )
    .is_err());
    assert!(super::admin::build_open_params(
        &gpr,
        Some("bootloader"),
        Some("ARM:LE:32:Cortex"),
        None,
        None,
        None,
        false,
        false,
    )
    .is_err());
    let gpr_params = super::admin::build_open_params(
        &gpr,
        Some("bootloader"),
        None,
        None,
        None,
        None,
        false,
        true,
    )
    .unwrap();
    assert_eq!(gpr_params["programName"], "bootloader");
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
