// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! The output of the CLI: JSON, aligned tables, and the conversion of tool results.

use crate::mcp::RawToolResult;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::fmt;
use std::io::{self, Write};
use std::process::ExitCode;

/// Writes `value` as formatted JSON, with a newline at the end.
pub fn write_json(mut writer: impl Write, value: &impl serde::Serialize) -> Result<()> {
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

/// Stops the process with status 0 if `error` is a closed pipe. The reader
/// of the output stopped, so the output has no use.
fn exit_on_closed_pipe(error: &io::Error) {
    if error.kind() == io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
}

/// Writes one line to stdout. The `out!` macro uses this function.
pub fn line(args: fmt::Arguments<'_>) {
    let mut stdout = io::stdout().lock();
    if let Err(error) = writeln!(stdout, "{args}").and_then(|()| stdout.flush()) {
        exit_on_closed_pipe(&error);
    }
}

/// Writes `value` as formatted JSON to stdout.
pub fn print_json(value: &impl serde::Serialize) -> Result<()> {
    let text = serde_json::to_string_pretty(value)?;
    line(format_args!("{text}"));
    Ok(())
}

/// Writes a tool result of `call`. For a success, it writes the structured
/// result to stdout. For a failure, it writes the structured result to stderr.
pub fn display_call(result: &RawToolResult) -> Result<ExitCode> {
    let value: Value = serde_json::from_str(result.structured_content.get())?;
    if result.is_error {
        write_json(io::stderr().lock(), &value)?;
        Ok(ExitCode::FAILURE)
    } else {
        write_json(io::stdout().lock(), &value)?;
        Ok(ExitCode::SUCCESS)
    }
}

/// Returns the structured result of a successful tool call.
///
/// # Errors
///
/// Fails with the error message of the tool if the call failed.
pub fn tool_value(result: &RawToolResult) -> Result<Value> {
    let value: Value = serde_json::from_str(result.structured_content.get())?;
    if !result.is_error {
        return Ok(value);
    }
    let message = value
        .pointer("/response/error/message")
        .and_then(Value::as_str)
        .map_or_else(|| "the tool call failed".to_string(), str::to_owned);
    Err(anyhow!(message))
}

/// Writes rows in columns with aligned widths. The first row is the header.
pub fn print_table(header: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = header.iter().map(|name| name.chars().count()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let header: Vec<String> = header.iter().map(|name| (*name).to_string()).collect();
    for row in std::iter::once(&header).chain(rows) {
        let line: Vec<String> = row
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        out!("{}", line.join("  ").trim_end());
    }
}

/// Returns a JSON field as text. A string has no quotes. An absent field is `-`.
pub fn text(value: &Value, field: &str) -> String {
    match value.get(field) {
        None | Some(Value::Null) => "-".to_string(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    }
}

/// Returns a duration in seconds as text, for example `1h 2m 3s`.
pub fn duration(seconds: u64) -> String {
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    match (hours, minutes) {
        (0, 0) => format!("{seconds}s"),
        (0, _) => format!("{minutes}m {seconds}s"),
        _ => format!("{hours}h {minutes}m {seconds}s"),
    }
}
