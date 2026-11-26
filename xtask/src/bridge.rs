// Copyright 2026 ByteLand Technology Limited
// SPDX-License-Identifier: MIT

//! Builds the Java bridge submodule with Gradle.
//!
//! The bridge outputs `ghidra-bridge.jar`, `Bridge.java` and `GhidraMcp.java` in
//! `bridge/build/ghidra-script/`. Rust code embeds these three files.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::workspace;

/// The directory of bridge distribution files, relative to the workspace root.
const BRIDGE_DIST: &str = "bridge/build/ghidra-script";

/// Returns the paths of the bridge JAR and the two launcher scripts.
pub(crate) fn artifact_paths() -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let root = workspace::root()?;
    let dist = root.join(BRIDGE_DIST);
    Ok((
        dist.join("ghidra-bridge.jar"),
        dist.join("Bridge.java"),
        dist.join("GhidraMcp.java"),
    ))
}

/// Returns `true` if all bridge artifacts exist.
pub(crate) fn artifacts_exist() -> Result<bool, String> {
    let (jar, bridge_script, mcp_script) = artifact_paths()?;
    Ok(jar.is_file() && bridge_script.is_file() && mcp_script.is_file())
}

/// Makes sure that the bridge artifacts exist. Builds them if they do not exist.
pub(crate) fn ensure_built() -> Result<(), String> {
    if artifacts_exist()? {
        Ok(())
    } else {
        println!("Bridge artifacts are missing. Building the bridge...");
        build(false)
    }
}

/// Builds the bridge submodule with Gradle.
pub(crate) fn build(force: bool) -> Result<(), String> {
    let root = workspace::root()?;
    let bridge_dir = root.join("bridge");
    let build_gradle = bridge_dir.join("build.gradle");

    if !build_gradle.exists() {
        return Err(format!(
            "The 'bridge' submodule is missing (not found: {}).\n\
       Initialize submodules with: git submodule update --init --recursive",
            build_gradle.display()
        ));
    }

    let (jar_path, bridge_script_path, mcp_script_path) = artifact_paths()?;
    if !force && jar_path.is_file() && bridge_script_path.is_file() && mcp_script_path.is_file() {
        println!("Bridge artifacts are up to date.");
        return Ok(());
    }

    let override_jar = env::var_os("GHIDRA_MCP_BRIDGE_JAR").map(PathBuf::from);
    if override_jar.is_some() {
        run_gradle(&bridge_dir, ":launcher:generateBridgeScript")?;
        run_gradle(&bridge_dir, ":launcher:generateMcpScript")?;
    } else {
        run_gradle(&bridge_dir, "buildGhidraScript")?;
    }

    if let Some(src_jar) = override_jar {
        let src_jar = if src_jar.is_absolute() {
            src_jar
        } else {
            root.join(src_jar)
        };
        if !src_jar.is_file() {
            return Err(format!(
                "GHIDRA_MCP_BRIDGE_JAR not found: {}",
                src_jar.display()
            ));
        }
        let dist = root.join(BRIDGE_DIST);
        fs::create_dir_all(&dist)
            .map_err(|err| format!("cannot create {}: {err}", dist.display()))?;
        fs::copy(&src_jar, &jar_path).map_err(|err| {
            format!(
                "cannot copy {} to {}: {err}",
                src_jar.display(),
                jar_path.display()
            )
        })?;
        for (name, destination) in [
            ("Bridge.java", &bridge_script_path),
            ("GhidraMcp.java", &mcp_script_path),
        ] {
            let generated = bridge_dir
                .join("modules/launcher/build/generated/scripts")
                .join(name);
            if generated.is_file() {
                fs::copy(&generated, destination).map_err(|err| {
                    format!(
                        "cannot copy {} to {}: {err}",
                        generated.display(),
                        destination.display()
                    )
                })?;
            }
        }
    }

    if !jar_path.is_file() || !bridge_script_path.is_file() || !mcp_script_path.is_file() {
        return Err(format!(
            "Gradle build succeeded, but artifacts are missing in {}",
            root.join(BRIDGE_DIST).display()
        ));
    }

    println!(
        "Bridge build complete: {}",
        root.join(BRIDGE_DIST).display()
    );
    Ok(())
}

fn run_gradle(bridge_dir: &Path, task: &str) -> Result<(), String> {
    let wrapper = if cfg!(windows) {
        "gradlew.bat"
    } else {
        "gradlew"
    };
    let mut command = Command::new(bridge_dir.join(wrapper));
    command.current_dir(bridge_dir).arg(task);

    if let Some(install_dir) =
        env::var_os("GHIDRA_INSTALL_DIR").or_else(|| env::var_os("GHIDRA_HOME"))
    {
        command.arg(format!(
            "-PghidraInstallDir={}",
            Path::new(&install_dir).display()
        ));
        command.env("GHIDRA_INSTALL_DIR", &install_dir);
    }

    for var in ["GHIDRA_HOME", "JAVA_HOME"] {
        if let Some(val) = env::var_os(var) {
            command.env(var, val);
        }
    }

    println!("> Running Gradle task: {task} in {}", bridge_dir.display());
    let status = command
        .status()
        .map_err(|err| format!("cannot execute Gradle: {err}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("Gradle task {task} failed with status {status}"))
    }
}
