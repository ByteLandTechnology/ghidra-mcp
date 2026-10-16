// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Builds the workspace and its bridge dependency.

use crate::bridge;
use crate::workspace;

/// Makes sure that the bridge exists, then runs `cargo build` with extra arguments.
pub(crate) fn run(args: &[&str]) -> Result<(), String> {
    bridge::ensure_built()?;
    let mut cmd = vec!["build"];
    cmd.extend_from_slice(args);
    workspace::cargo(&cmd)
}
