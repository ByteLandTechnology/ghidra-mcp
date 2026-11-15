// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Makes the npm packages from the release executables.
//!
//! The main package `@ghidra-mcp/cli` holds a JavaScript launcher.
//! Each platform package holds one native executable. npm installs only the
//! platform package that agrees with the `os`, `cpu`, and `libc` fields.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::workspace;

/// The npm scope of all packages.
const SCOPE: &str = "@ghidra-mcp";

/// The directory of the main package, relative to the workspace root.
const MAIN_DIR: &str = "npm/cli";

/// The launcher file of the main package, relative to the main package.
const LAUNCHER: &str = "bin/ghidra-mcp.js";

/// One platform package and the CI artifact that it holds.
pub(crate) struct Platform {
    /// The package name after the scope, as `<os>-<cpu>`.
    pub(crate) suffix: &'static str,
    /// The file name of the executable in the release `dist` directory.
    pub(crate) artifact: &'static str,
    /// The npm `os` value.
    pub(crate) os: &'static str,
    /// The npm `cpu` value.
    pub(crate) cpu: &'static str,
    /// The npm `libc` value, if the executable needs a specified C library.
    pub(crate) libc: Option<&'static str>,
}

impl Platform {
    /// Returns the full npm package name.
    pub(crate) fn package(&self) -> String {
        format!("{SCOPE}/{}", self.suffix)
    }

    /// Returns the executable file name in the package `bin` directory.
    pub(crate) fn executable(&self) -> &'static str {
        if self.os == "win32" {
            "ghidra-mcp.exe"
        } else {
            "ghidra-mcp"
        }
    }
}

/// All platform packages. The CI build matrix makes one artifact for each.
pub(crate) const PLATFORMS: [Platform; 6] = [
    Platform {
        suffix: "darwin-arm64",
        artifact: "ghidra-mcp-macos-arm64",
        os: "darwin",
        cpu: "arm64",
        libc: None,
    },
    Platform {
        suffix: "darwin-x64",
        artifact: "ghidra-mcp-macos-x86_64",
        os: "darwin",
        cpu: "x64",
        libc: None,
    },
    Platform {
        suffix: "linux-arm64",
        artifact: "ghidra-mcp-linux-arm64",
        os: "linux",
        cpu: "arm64",
        libc: Some("glibc"),
    },
    Platform {
        suffix: "linux-x64",
        artifact: "ghidra-mcp-linux-x86_64",
        os: "linux",
        cpu: "x64",
        libc: Some("glibc"),
    },
    Platform {
        suffix: "win32-arm64",
        artifact: "ghidra-mcp-windows-arm64.exe",
        os: "win32",
        cpu: "arm64",
        libc: None,
    },
    Platform {
        suffix: "win32-x64",
        artifact: "ghidra-mcp-windows-x86_64.exe",
        os: "win32",
        cpu: "x64",
        libc: None,
    },
];

/// Makes all npm packages in `out` from the executables in `dist`.
///
/// The `out` directory must be absent or empty.
/// Each package goes into `out/<suffix>`, and the main package goes into `out/cli`.
pub(crate) fn pack(dist: &Path, out: &Path) -> Result<(), String> {
    let root = workspace::root()?;
    let template = read_json(&root.join(MAIN_DIR).join("package.json"))?;
    let version = template_version(&template)?;
    let cargo_version = cargo_version(&workspace::read(&root.join("Cargo.toml"))?)?;
    if version != cargo_version {
        return Err(format!(
            "{MAIN_DIR}/package.json has version {version}, but Cargo.toml has {cargo_version}"
        ));
    }
    prepare_out(out)?;

    let licenses = [
        (root.join("LICENSE"), "LICENSE"),
        (root.join("bridge").join("LICENSE"), "LICENSE-ghidra-bridge"),
        (
            dist.join("THIRD_PARTY_LICENSES.txt"),
            "THIRD_PARTY_LICENSES.txt",
        ),
    ];

    for platform in &PLATFORMS {
        let source = dist.join(platform.artifact);
        if !source.is_file() {
            return Err(format!("{}: the executable is absent", source.display()));
        }
        let directory = out.join(platform.suffix);
        let bin = directory.join("bin");
        create_dir(&bin)?;
        let target = bin.join(platform.executable());
        copy(&source, &target)?;
        make_executable(&target)?;
        for (license, name) in &licenses {
            if license.is_file() {
                copy(license, &directory.join(name))?;
            }
        }
        write_json(
            &directory.join("package.json"),
            &platform_manifest(platform, &template, &version),
        )?;
        println!(
            "{}@{version}: {}",
            platform.package(),
            workspace::display(&directory)
        );
    }

    let directory = out.join("cli");
    create_dir(&directory.join("bin"))?;
    let launcher = directory.join(LAUNCHER);
    copy(&root.join(MAIN_DIR).join(LAUNCHER), &launcher)?;
    make_executable(&launcher)?;
    copy(&root.join("README.md"), &directory.join("README.md"))?;
    copy(&root.join("LICENSE"), &directory.join("LICENSE"))?;
    write_json(
        &directory.join("package.json"),
        &main_manifest(template, &version)?,
    )?;
    println!("{SCOPE}/cli@{version}: {}", workspace::display(&directory));
    Ok(())
}

/// Returns the `version` string of the main package template.
fn template_version(template: &Value) -> Result<String, String> {
    template
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{MAIN_DIR}/package.json has no version string"))
}

/// Returns the `version` value from the `[package]` table of `Cargo.toml`.
fn cargo_version(manifest: &str) -> Result<String, String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(rest) = line.strip_prefix("version") {
            let value = rest.trim_start().trim_start_matches('=').trim();
            return Ok(value.trim_matches('"').to_owned());
        }
    }
    Err("Cargo.toml has no package version".to_owned())
}

/// Returns the main package manifest, with the platform packages at `version`.
fn main_manifest(mut template: Value, version: &str) -> Result<Value, String> {
    let object = template
        .as_object_mut()
        .ok_or_else(|| format!("{MAIN_DIR}/package.json is not a JSON object"))?;
    let dependencies: Map<String, Value> = PLATFORMS
        .iter()
        .map(|platform| (platform.package(), Value::from(version)))
        .collect();
    object.insert("version".to_owned(), Value::from(version));
    object.insert(
        "optionalDependencies".to_owned(),
        Value::Object(dependencies),
    );
    Ok(template)
}

/// Returns the manifest of one platform package.
///
/// The license and repository fields come from the main package template.
fn platform_manifest(platform: &Platform, template: &Value, version: &str) -> Value {
    let mut manifest = json!({
        "name": platform.package(),
        "version": version,
        "description": format!(
            "The ghidra-mcp executable for {} {}.",
            platform.os, platform.cpu
        ),
        "license": template.get("license").cloned().unwrap_or(Value::Null),
        "repository": template.get("repository").cloned().unwrap_or(Value::Null),
        "os": [platform.os],
        "cpu": [platform.cpu],
        "files": ["bin", "LICENSE*", "THIRD_PARTY_LICENSES.txt"],
        "preferUnplugged": true,
    });
    if let (Some(libc), Some(object)) = (platform.libc, manifest.as_object_mut()) {
        object.insert("libc".to_owned(), json!([libc]));
    }
    manifest
}

/// Makes sure that `out` exists and is empty.
fn prepare_out(out: &Path) -> Result<(), String> {
    if out.exists() {
        let mut entries =
            fs::read_dir(out).map_err(|error| format!("{}: {error}", out.display()))?;
        if entries.next().is_some() {
            return Err(format!("{}: the directory is not empty", out.display()));
        }
    }
    create_dir(out)
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_str(&workspace::read(path)?)
        .map_err(|error| format!("{}: invalid JSON: {error}", workspace::display(path)))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    text.push('\n');
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

fn create_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn copy(source: &Path, target: &Path) -> Result<(), String> {
    fs::copy(source, target)
        .map(|_| ())
        .map_err(|error| format!("{} -> {}: {error}", source.display(), target.display()))
}

/// Sets the Unix mode 0755. On other systems, this function does nothing.
fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("{}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
#[path = "npm_tests.rs"]
mod tests;
