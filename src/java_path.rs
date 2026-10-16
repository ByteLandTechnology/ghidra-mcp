// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Path conversion for Java and Ghidra.

use std::io;
use std::path::{Path, PathBuf};

/// Prepares a path for Java and for the Ghidra launch scripts.
///
/// On Unix, the function returns the path without changes. Then Ghidra sees the
/// project launch alias, not the hidden physical path. On Windows, the path
/// becomes absolute, and the function removes the verbatim prefix `\\?\` of
/// Rust. The batch launchers and Java do not accept this prefix. The function
/// does not resolve symbolic links.
///
/// # Errors
///
/// On Windows, fails if the function needs the current directory and cannot get it.
#[cfg_attr(
  unix,
  expect(
    clippy::unnecessary_wraps,
    reason = "the Windows conversion can fail; both platforms share the signature"
  )
)]
pub fn java_path(path: &Path) -> io::Result<PathBuf> {
  #[cfg(unix)]
  {
    Ok(path.to_path_buf())
  }
  #[cfg(windows)]
  {
    std::path::absolute(dunce::simplified(path))
  }
}
