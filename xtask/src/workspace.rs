// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Finds workspace paths and files for xtask.

use std::fs;
use std::path::{Path, PathBuf};

/// Returns the workspace root, which is the parent of the xtask crate.
pub(crate) fn root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "the xtask crate has no parent directory".to_owned())
}

/// Returns `path` relative to the workspace root, for display messages.
pub(crate) fn display(path: &Path) -> String {
    match root() {
        Ok(root) => path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string(),
        Err(_) => path.display().to_string(),
    }
}

/// Reads a file as UTF-8 text.
pub(crate) fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("{}: {error}", display(path)))
}

/// Returns each `.rs` file of the workspace, sorted by path.
pub(crate) fn rust_files() -> Result<Vec<PathBuf>, String> {
    let root = root()?;
    let mut files = Vec::new();
    walk(&root, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(directory).map_err(|error| format!("{}: {error}", display(directory)))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("{}: {error}", display(directory)))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(
            name.as_str(),
            ".git" | ".agents" | ".worktrees" | ".cache" | "target" | "node_modules"
        ) {
            continue;
        }
        let kind = entry
            .file_type()
            .map_err(|error| format!("{}: {error}", display(&path)))?;
        if kind.is_dir() {
            walk(&path, files)?;
        } else if kind.is_file() && name.ends_with(".rs") {
            files.push(path);
        }
    }
    Ok(())
}

/// Runs a Cargo command with the given arguments in the workspace root.
pub(crate) fn cargo(args: &[&str]) -> Result<(), String> {
    let program = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    println!("> cargo {}", args.join(" "));
    let status = std::process::Command::new(program)
        .args(args)
        .current_dir(root()?)
        .status()
        .map_err(|error| format!("cannot run cargo {}: {error}", args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo {} failed", args.join(" ")))
    }
}
