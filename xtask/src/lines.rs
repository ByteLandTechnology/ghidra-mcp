// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Checks the line count and line width limits of each Rust file.

use crate::{lexer, workspace};

/// The largest number of code lines in one file.
const CODE_LINE_LIMIT: usize = 800;

/// The largest width (number of characters) of one line.
const LINE_WIDTH_LIMIT: usize = 100;

/// Makes sure that no Rust file has more than [`CODE_LINE_LIMIT`] lines of code.
/// Comments and blank lines are not counted.
pub(crate) fn check_code_lines() -> Result<(), String> {
    let mut over = Vec::new();
    for path in workspace::rust_files()? {
        let source = workspace::read(&path)?;
        let count = lexer::lex(&source)
            .iter()
            .filter(|line| line.has_code)
            .count();
        if count > CODE_LINE_LIMIT {
            over.push((count, workspace::display(&path)));
        }
    }
    if over.is_empty() {
        println!("Line limit: OK");
        return Ok(());
    }
    over.sort_by(|left, right| right.cmp(left));
    let list: Vec<String> = over
        .iter()
        .map(|(count, path)| format!("  {count}\t{path}"))
        .collect();
    Err(format!(
        "Line limit: these files have more than {CODE_LINE_LIMIT} lines of code:\n{}",
        list.join("\n")
    ))
}

/// Makes sure that no line in any Rust file exceeds [`LINE_WIDTH_LIMIT`] characters.
pub(crate) fn check_line_widths() -> Result<(), String> {
    let mut over = Vec::new();
    for path in workspace::rust_files()? {
        let source = workspace::read(&path)?;
        for (number, line) in source.lines().enumerate() {
            let width = line.chars().count();
            if width > LINE_WIDTH_LIMIT {
                over.push((workspace::display(&path), number + 1, width));
            }
        }
    }
    if over.is_empty() {
        println!("Line width: OK");
        return Ok(());
    }
    let list: Vec<String> = over
        .iter()
        .map(|(path, number, width)| format!("  {path}:{number} ({width} > {LINE_WIDTH_LIMIT})"))
        .collect();
    Err(format!(
        "Line width: these lines exceed {LINE_WIDTH_LIMIT} characters:\n{}",
        list.join("\n")
    ))
}
