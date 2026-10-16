// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Checks the license header of each Rust file.

use std::fs;

use crate::workspace;

const COPYRIGHT: &str = "// Copyright 2026 ByteLand Technology Limited";
const SPDX: &str = "// SPDX-License-Identifier: MIT";

/// Makes sure that each Rust file starts with the license header. With
/// `fix`, adds the header to each file that does not have it.
pub(crate) fn check(fix: bool) -> Result<(), String> {
  let mut missing = Vec::new();
  for path in workspace::rust_files()? {
    let source = workspace::read(&path)?;
    let mut lines = source.lines();
    if lines.next() == Some(COPYRIGHT) && lines.next() == Some(SPDX) {
      continue;
    }
    if fix {
      let fixed = format!("{COPYRIGHT}\n{SPDX}\n\n{source}");
      fs::write(&path, fixed).map_err(|error| format!("{}: {error}", workspace::display(&path)))?;
    }
    missing.push(workspace::display(&path));
  }
  if missing.is_empty() {
    println!("License headers: OK");
    Ok(())
  } else if fix {
    println!("License headers: added to {} file(s)", missing.len());
    Ok(())
  } else {
    Err(format!(
      "License headers: missing or incorrect in {} file(s):\n  {}\n\
             Run `cargo xtask license-headers --fix` to add them.",
      missing.len(),
      missing.join("\n  ")
    ))
  }
}
