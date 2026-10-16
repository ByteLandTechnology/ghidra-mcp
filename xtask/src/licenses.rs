// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Collects third-party license notices for locked dependencies and embedded bridge.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::workspace;

#[derive(Debug, Deserialize)]
struct Metadata {
  packages: Vec<Package>,
  workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Package {
  id: String,
  name: String,
  version: String,
  license: Option<String>,
  license_file: Option<String>,
  repository: Option<String>,
  manifest_path: String,
}

pub(crate) fn collect() -> Result<(), String> {
  let root = workspace::root()?;
  let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

  let output = Command::new(cargo)
    .args(["metadata", "--locked", "--format-version=1"])
    .current_dir(&root)
    .output()
    .map_err(|e| format!("cannot run cargo metadata: {e}"))?;

  if !output.status.success() {
    return Err(format!(
      "cargo metadata failed: {}",
      String::from_utf8_lossy(&output.stderr)
    ));
  }

  let metadata: Metadata = serde_json::from_slice(&output.stdout)
    .map_err(|e| format!("cannot parse cargo metadata: {e}"))?;

  let apache_license = workspace::read(&root.join("bridge/LICENSE"))?;
  let root_license = workspace::read(&root.join("LICENSE"))?;

  let mut sections = vec![
    concat!(
      "ghidra-mcp: licenses and source locations\n",
      "This file includes all locked Rust dependencies. ",
      "It also includes build dependencies and targets for other platforms.\n"
    )
    .to_owned(),
    format!("ghidra-mcp\n{root_license}"),
    format!(
      "ghidra-bridge\nSource: https://github.com/ByteLandTechnology/ghidra-bridge\n{apache_license}"
    ),
  ];

  let workspace_members: BTreeSet<&str> = metadata
    .workspace_members
    .iter()
    .map(String::as_str)
    .collect();

  let mut packages: Vec<&Package> = metadata
    .packages
    .iter()
    .filter(|p| !workspace_members.contains(p.id.as_str()))
    .collect();

  packages.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));

  for pkg in packages {
    let manifest_path = Path::new(&pkg.manifest_path);
    let directory = manifest_path
      .parent()
      .ok_or_else(|| format!("invalid manifest path: {}", pkg.manifest_path))?;

    let mut license_files = BTreeSet::new();
    find_license_files(directory, &mut license_files)?;

    if let Some(ref file) = pkg.license_file {
      let extra = directory.join(file);
      if extra.is_file() {
        license_files.insert(extra);
      }
    }

    let repo_info = pkg.repository.as_deref().unwrap_or("see source archive");
    let license_name = pkg.license.as_deref().unwrap_or("");
    let mut section = format!(
      concat!(
        "{} {}\nLicense: {}\nRepository: {}\n",
        "Source: https://crates.io/api/v1/crates/{}/{}/download\n"
      ),
      pkg.name, pkg.version, license_name, repo_info, pkg.name, pkg.version
    );

    if !license_files.is_empty() {
      for file_path in license_files {
        let relative = file_path
          .strip_prefix(directory)
          .unwrap_or(&file_path)
          .display();
        let content = fs::read_to_string(&file_path)
          .map_err(|e| format!("cannot read {}: {e}", file_path.display()))?
          .replace("\r\n", "\n");
        section.push_str(&format!("\n--- {relative} ---\n{content}"));
      }
    } else if license_name.split_whitespace().any(|s| s == "Apache-2.0") {
      section.push_str(&format!(
        "\nApache-2.0 license text (see source archive for authorship):\n{apache_license}"
      ));
    } else {
      return Err(format!(
        "No license text for {} {}; inspect the source archive",
        pkg.name, pkg.version
      ));
    }

    sections.push(section);
  }

  println!("{}", sections.join("\n\n"));
  Ok(())
}

fn find_license_files(dir: &Path, files: &mut BTreeSet<PathBuf>) -> Result<(), String> {
  let entries = fs::read_dir(dir).map_err(|e| format!("cannot read dir {}: {e}", dir.display()))?;
  for entry in entries {
    let entry = entry.map_err(|e| format!("cannot read entry: {e}"))?;
    let path = entry.path();
    let file_type = entry
      .file_type()
      .map_err(|e| format!("cannot read file type: {e}"))?;

    if file_type.is_dir() {
      find_license_files(&path, files)?;
    } else if file_type.is_file() {
      let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

      if file_name.starts_with("license")
        || file_name.starts_with("licence")
        || file_name.starts_with("copying")
        || file_name.starts_with("notice")
      {
        files.insert(path);
      }
    }
  }
  Ok(())
}
