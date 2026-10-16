// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Finds the `analyzeHeadless` launcher of Ghidra, and calculates the MD5 of binaries.

use crate::config::McpConfig;
use anyhow::{bail, Context, Result};
use std::env;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// The file name of the headless launcher of Ghidra.
#[cfg(windows)]
const ANALYZE_HEADLESS: &str = "analyzeHeadless.bat";
/// The file name of the headless launcher of Ghidra.
#[cfg(not(windows))]
const ANALYZE_HEADLESS: &str = "analyzeHeadless";
/// The file name of the GUI launcher of Ghidra. It is more frequently on `PATH`.
#[cfg(windows)]
const GHIDRA_RUN: &str = "ghidraRun.bat";
/// The file name of the GUI launcher of Ghidra. It is more frequently on `PATH`.
#[cfg(not(windows))]
const GHIDRA_RUN: &str = "ghidraRun";

/// Finds `analyzeHeadless`. It tries these locations in sequence:
///
/// 1. `[ghidra].analyze_headless` in the configuration, without a check.
/// 2. The installation in `[ghidra].home`, `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME`.
/// 3. `analyzeHeadless` on `PATH`.
/// 4. The installation of a `ghidraRun` on `PATH`.
/// 5. On Unix, the Homebrew Cellar, and then the `ghidra*` directories in
///    `/Applications`, `~`, `~/Applications` and `~/opt`.
///
/// # Errors
///
/// Fails if no location has `analyzeHeadless`.
pub fn analyze_headless(config: &McpConfig) -> Result<PathBuf> {
  if let Some(explicit) = &config.ghidra.analyze_headless {
    return Ok(PathBuf::from(explicit));
  }
  let install_dirs = config.ghidra.home.iter().map(PathBuf::from).chain(
    ["GHIDRA_INSTALL_DIR", "GHIDRA_HOME"]
      .into_iter()
      .filter_map(|key| env::var_os(key).map(PathBuf::from)),
  );
  for install_dir in install_dirs {
    if let Some(candidate) = analyze_headless_in(&install_dir) {
      return Ok(candidate);
    }
  }
  if let Ok(candidate) = which::which(ANALYZE_HEADLESS) {
    return Ok(candidate);
  }
  if let Some(candidate) = which::which(GHIDRA_RUN)
    .ok()
    .and_then(|ghidra_run| analyze_headless_near(&ghidra_run))
  {
    return Ok(candidate);
  }
  #[cfg(unix)]
  if let Some(candidate) = find_in_common_locations() {
    return Ok(candidate);
  }
  bail!("{ANALYZE_HEADLESS} not found; set GHIDRA_INSTALL_DIR or add its directory to PATH")
}

/// Returns `analyzeHeadless` in an installation directory, also in a macOS app bundle.
fn analyze_headless_in(install_dir: &Path) -> Option<PathBuf> {
  [
    install_dir.join("support"),
    install_dir.join("Contents/Resources/Java/support"),
  ]
  .into_iter()
  .map(|support| support.join(ANALYZE_HEADLESS))
  .find(|candidate| candidate.is_file())
}

/// Returns `analyzeHeadless` in the installation of `ghidra_run`. The function
/// tries the path and its symbolic link target. Package managers frequently
/// put a link to `ghidraRun` in a `bin` directory.
fn analyze_headless_near(ghidra_run: &Path) -> Option<PathBuf> {
  let canonical = ghidra_run.canonicalize().ok();
  let found = [Some(ghidra_run), canonical.as_deref()]
    .into_iter()
    .flatten()
    .filter_map(Path::parent)
    .flat_map(|dir| dir.ancestors().take(4))
    .flat_map(|ancestor| {
      [
        ancestor.join("support").join(ANALYZE_HEADLESS),
        ancestor.join("libexec/support").join(ANALYZE_HEADLESS),
      ]
    })
    .find(|candidate| candidate.is_file());
  found
}

/// Searches the Homebrew Cellar (newest version first). Then it searches the
/// directories with `ghidra` in their names in the usual install locations.
#[cfg(unix)]
fn find_in_common_locations() -> Option<PathBuf> {
  for cellar in ["/opt/homebrew/Cellar/ghidra", "/usr/local/Cellar/ghidra"] {
    let newest_first = subdirectories(Path::new(cellar)).into_iter().rev();
    if let Some(candidate) = newest_first
      .map(|version| version.join("libexec/support").join(ANALYZE_HEADLESS))
      .find(|candidate| candidate.is_file())
    {
      return Some(candidate);
    }
  }
  let mut roots = vec![PathBuf::from("/Applications")];
  if let Some(home) = env::var_os("HOME").map(PathBuf::from) {
    roots.extend([home.join("Applications"), home.join("opt"), home]);
  }
  roots
    .iter()
    .flat_map(|root| subdirectories(root))
    .filter(|dir| {
      dir.file_name().is_some_and(|name| {
        name
          .to_string_lossy()
          .to_ascii_lowercase()
          .contains("ghidra")
      })
    })
    .find_map(|dir| analyze_headless_in(&dir))
}

/// Returns the subdirectories of `root`, sorted by name. Returns an empty list
/// if it cannot read `root`.
#[cfg(unix)]
fn subdirectories(root: &Path) -> Vec<PathBuf> {
  let Ok(entries) = std::fs::read_dir(root) else {
    return Vec::new();
  };
  let mut dirs: Vec<PathBuf> = entries
    .filter_map(Result::ok)
    .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
    .map(|entry| entry.path())
    .collect();
  dirs.sort();
  dirs
}

/// Calculates the lowercase hexadecimal MD5 of a file. It reads the file in parts.
///
/// # Errors
///
/// Fails if the function cannot open or read the file.
pub fn file_md5(path: &Path) -> Result<String> {
  let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
  let mut context = md5::Context::new();
  io::copy(&mut file, &mut context).with_context(|| format!("reading {}", path.display()))?;
  Ok(format!("{:x}", context.compute()))
}
