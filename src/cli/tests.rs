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
