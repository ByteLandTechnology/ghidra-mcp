// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Runs repository and format checks in CI order.

use crate::bridge;
use crate::workspace;

/// Runs CI checks: fmt check, repository checks, bridge check, clippy, doc.
pub(crate) fn run() -> Result<(), String> {
    workspace::cargo(&["fmt", "--all", "--", "--check"])?;
    crate::run_all()?;
    bridge::ensure_built()?;
    workspace::cargo(&[
        "clippy",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ])?;
    workspace::cargo(&["doc", "--no-deps", "--document-private-items", "--locked"])?;
    println!("CI: OK");
    Ok(())
}
